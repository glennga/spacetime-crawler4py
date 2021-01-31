import re
import shelve
import time
import pickle
import hashlib

from utils import get_logger
from urllib.parse import urlparse, urljoin
from lxml import etree, html
from utils.download import download


logger = get_logger('Scraper')


class _Tokenizer:
    class Token:
        def __init__(self, token: str, tag):
            self.token = token
            self.tag = tag

        def __str__(self):
            return self.token

    def __init__(self):
        self.stop_words = set(
            'a,able,about,across,after,all,almost,also,am,among,an,and,any,are,as,at,be,because,been,'
            'but,by,can,cannot,could,dear,did,do,does,either,else,ever,every,for,from,get,got,had,has,'
            'have,he,her,hers,him,his,how,however,i,if,in,into,is,it,its,just,least,let,like,likely,'
            'may,me,might,most,must,my,neither,no,nor,not,of,off,often,on,only,or,other,our,own,rather,'
            'said,say,says,she,should,since,so,some,than,that,the,their,them,then,there,these,they,'
            'this,tis,to,too,twas,us,wants,was,we,were,what,when,where,which,while,who,whom,why,will,'
            'with,would,yet,you,your'.split(',')
        )

    def tokenize_page(self, url, page_text) -> list:
        """ :return: A list of tokens. """
        tokens = list()

        try:
            root = html.fromstring(page_text)
            for element in root.iter():
                try:
                    # Conditions: a) text must be not null, b) the element must have a 'simple' tag, and c) the
                    # element tag must not be a script or a style tag.
                    if element.text is not None and type(element.tag) == str and \
                            element.tag != 'script' and element.tag != 'style':

                        # Conditions: a) tokens are delimited by non alphabet characters, b) tokens are greater than 1
                        # character, and c) tokens are not stop words.
                        for word in re.split(r"[^a-zA-Z]+", element.text):
                            if len(word) > 1 and word.lower() not in self.stop_words:
                                tokens.append(self.Token(word.lower(), element.tag))

                except UnicodeDecodeError as e:
                    logger.warn(f"Unicode error parsing URL {url}. {e}.")

            return tokens

        except etree.ParserError as e:
            logger.error(f'Could not tokenize page for URL {url}. Error: {e}')
            return list()


class _Auditor:
    def __init__(self, config):
        self.config = config
        self.token_logger = get_logger('Token')
        self.url_logger = get_logger('Link')
        with shelve.open(self.config.longest_page_file) as db:
            self.longest_page_stat = (db["largest"][0], db["largest"][1]) if "largest" in db else ("", 0)

    def handle_q1(self, url):
        parsed = urlparse(url)  # This is to be handled offline (i.e. looking at the log files).
        self.url_logger.info(f'Auditing URL {parsed.netloc + parsed.path}')

    def handle_q2(self, url, n):
        if n > self.longest_page_stat[1]:
            self.longest_page_stat = (url, n)
            logger.info(f'New longest page found: "{url}" with {n} words.')
            with shelve.open(self.config.longest_page_file) as db:
                db["largest"] = self.longest_page_stat

    def handle_q3(self, url, tokens):
        self.token_logger.info("Processing tokens from url: " + url)
        with shelve.open(self.config.common_words_file) as db:
            old_token_db = set(token[0] for token in sorted(db.items(), key=lambda x: [-x[1], x[0]])[:50])
            for token in tokens:
                if token and token not in db:
                    db[token] = 1
                    self.token_logger.debug(f'New token added to dictionary: {token}')

                elif token:
                    db[token] += 1
                    self.token_logger.debug(f'Incrementing token count for token: {token}')
            new_token_db = set(token[0] for token in sorted(db.items(), key=lambda x: [-x[1], x[0]])[:50])

            words_entering = set(token for token in new_token_db if token not in old_token_db)
            words_leaving = set(token for token in old_token_db if token not in new_token_db)
            if len(words_entering) != 0:
                self.token_logger.info("New words entering Top 50: " + str(words_entering))
            if len(words_leaving) != 0:
                self.token_logger.info("Words leaving top 50: " + str(words_leaving))
            self.token_logger.info("Top 50 tokens now: " + str(sorted(db.items(), key=lambda x: [-x[1], x[0]])[:50]))

    def handle_q4(self, url):
        # Note: we are assuming that unique URLs are being given here.
        with shelve.open(self.config.ics_subdomain_file) as db:
            parsed = urlparse(url)
            is_ics_subdomain = re.match(r".*\.ics\.uci\.edu.*", parsed.netloc.lower())
            logger.debug('Subdomain check for ' + parsed.netloc.lower() + " returns " + repr(is_ics_subdomain))
            if is_ics_subdomain and parsed.netloc.lower() not in db:
                db[parsed.netloc.lower()] = 1
                logger.info(f'Found new subdomain for ics.uci.edu: {parsed.netloc.lower()}')
            elif is_ics_subdomain:
                db[parsed.netloc.lower()] += 1
                logger.info(f'Incrementing count for existing subdomain: {parsed.netloc.lower()}')
            else:
                logger.debug("The entry " + parsed.netloc.lower() + " is not a subdomain")


class _Enforcer:
    class URLIterable:
        """ When called by the worker thread, we introduce a delay before returning the associated URL. """
        def __init__(self):
            self.links, self.delays = [], []
            self.current_position = 0

        def append_url(self, url, delay):
            self.links.append(url)
            self.delays.append(delay)

        def __iter__(self):
            return self

        def __next__(self):
            if self.current_position >= len(self.delays):
                raise StopIteration

            time.sleep(self.delays[self.current_position])
            url = self.links[self.current_position]
            self.current_position += 1
            return url

        def __str__(self):
            return str(self.links)

    def __init__(self, config):
        self.large_page_threshold_bytes = 1.0e8
        self.retry_set = set()
        self.config = config

        logger.info(f"Setting large page threshold to be: {self.large_page_threshold_bytes} bytes.")

    def check_retry(self, url, resp) -> bool:
        # As per Piazza post @17, we are to retry requests that return a status 500.
        if resp.status == 500 and url not in self.retry_set:
            logger.warn(f"URL {url} returned status code 500. Retrying.")
            self.retry_set.add(url)
            return True

        elif url in self.retry_set:
            logger.warn(f"URL {url} requested more than once. Not retrying again.")
            self.retry_set.remove(url)
            return False

        return False

    def validate_response(self, url, resp) -> bool:
        if resp.status != 200:
            logger.warn(f"Page found w/ non-200 status code: {url}")
            return False

        elif len(resp.raw_response.content) > self.large_page_threshold_bytes:
            logger.warn(f"Page found w/ size greater than large page threshold: {url} of size "
                        f"{len(resp.raw_response.content)} bytes.")
            return False

        return True

    def validate_tokens(self, url, tokens) -> bool:
        """ :return True if a) the token count of paragraph tags is non-zero and b) these paragraph tokens have not
            been found elsewhere. False otherwise. """
        paragraph_tokens = list(t for t in tokens if t.tag == 'p')
        if len(paragraph_tokens) == 0:
            logger.debug(f"URL {url} found without any paragraph tags. Skipping.")
            return False

        token_hash = hashlib.md5(pickle.dumps(paragraph_tokens)).hexdigest()
        with shelve.open(self.config.tokens_file) as tokens_shelf:
            if token_hash in tokens_shelf:
                logger.debug(f"URL {url} found with similar content to URL {tokens_shelf[token_hash]}.")
                return False

            else:
                logger.debug(f"URL {url} has a unique token hash: {token_hash}.")
                tokens_shelf[token_hash] = url
                return True

    def _fetch_robots(self, parsed):
        """ :return 1) the time in seconds that indicates **additional** time to wait,
            and 2) a list of paths to avoid.  """
        crawl_delay_delta, disallowed_paths = 0, list()

        robots_url = parsed.scheme + '://' + parsed.netloc.lower() + '/robots.txt'
        if not is_valid(robots_url):
            logger.warn(f"URL {robots_url} is invalid, and cannot be fetched.")
            return crawl_delay_delta, disallowed_paths

        else:
            time.sleep(self.config.time_delay)  # Respect our configured delay...
            resp = download(robots_url, self.config, logger)

        if resp.status != 200:
            logger.warn(f'Could not find robots.txt file for site {robots_url}.')

        else:
            try:
                for line in resp.raw_response.text.split('\n'):
                    if len(line.strip()) > 0 and line.strip()[0] == '#':
                        continue

                    if 'crawl-delay' in line.lower():  # Crawl delays are in seconds.
                        crawl_delay_s = float(self._get_content_in_robots_line(line))
                        logger.info(f'crawl-delay found for site {robots_url} of {crawl_delay_s} seconds.')
                        crawl_delay_delta = max(crawl_delay_s, self.config.time_delay) - self.config.time_delay

                    elif 'disallow' in line.lower():
                        disallowed_path = self._get_content_in_robots_line(line)
                        if '/' == disallowed_path[-1]:
                            disallowed_path = disallowed_path[:-1]

                        logger.info(f'Disallowing path: {disallowed_path} for site {robots_url}.')
                        disallowed_paths.append(disallowed_path.replace('*', '.*').replace('/', '\/'))

            except IndexError as e:
                logger.warn(f'Malformed robots.txt file for {robots_url}. Swallowing error: {e}')

            if crawl_delay_delta == 0:
                logger.info(f'Could not find crawl-delay in robots.txt file for site {robots_url}. Using default '
                            f'delay of {self.config.time_delay} seconds.')

        return crawl_delay_delta, disallowed_paths

    @staticmethod
    def _get_content_in_robots_line(line) -> str:
        """ :return Text in between the ":" and the potential '#'. """
        element = line.split(':')[1].strip()
        return element if '#' not in element else element.split('#')[0].strip()

    def enforce_links(self, links) -> iter:
        robots_table = shelve.open(self.config.robots_file)
        enforced_links = _Enforcer.URLIterable()

        for link in links:
            if not is_valid(link):
                continue

            parsed = urlparse(link)  # Update our robots table.
            if parsed.netloc.lower() not in robots_table:
                robots_table[parsed.netloc.lower()] = self._fetch_robots(parsed)

            crawl_delay_delta, disallowed_links = robots_table[parsed.netloc.lower()]
            if any(re.match(disallowed_link, parsed.path) for disallowed_link in disallowed_links):
                continue

            # Avoid any URLs we explicitly mention avoiding in our config file.
            if any(bool(link in x) for x in self.config.avoid_urls):
                continue

            enforced_links.append_url(link, crawl_delay_delta)

        robots_table.close()
        return enforced_links


class Scraper:
    def __init__(self, config):
        self.config = config
        self.tokenizer = _Tokenizer()
        self.auditor = _Auditor(self.config)
        self.enforcer = _Enforcer(self.config)

    def scrape(self, url, resp) -> (set, bool):
        # noinspection PyBroadException
        try:
            links, retry = self.extract_next_links(url, resp)
            enforced_links = self.enforcer.enforce_links(links)
            logger.info(f'Returning the following extracted links: {enforced_links}')
            return enforced_links, retry

        except Exception as e:
            logger.error(f"Error caught and swallowed for URL {url}! {e}")
            return list(), False

    def extract_next_links(self, url, resp) -> (set, bool):
        if self.enforcer.check_retry(url, resp):
            return {url}, True

        if not self.enforcer.validate_response(url, resp):
            return set(), False

        # Walk the page tree once to tokenize.
        tokens = self.tokenizer.tokenize_page(url, resp.raw_response.content)
        if not self.enforcer.validate_tokens(url, tokens):
            return set(), False

        # Audit this page (for our report questions).
        raw_tokens = set(str(t) for t in tokens)
        self.auditor.handle_q1(url)
        self.auditor.handle_q2(url, len(raw_tokens))
        self.auditor.handle_q3(url, raw_tokens)
        self.auditor.handle_q4(url)

        # Walk the page tree again to collect links.
        extracted_links = list()
        try:
            root = html.fromstring(resp.raw_response.content)
            links = [urljoin(url, u.get('href')) for u in root.cssselect('a')]

            for url in links:
                parsed = urlparse(url)
                # Separated the filtered url parsing in case we need to log this.
                filtered_url = (parsed.scheme + "://" + parsed.netloc + parsed.path
                                # TODO: Do we keep the params and query?
                                + ((";" + parsed.params) if len(parsed.params) > 0 else "")
                                + (("?" + parsed.query) if len(parsed.query) > 0 else ""))

                if url != filtered_url:
                    logger.debug(f"Filtered URL: {filtered_url} from {url}.")
                extracted_links.append(filtered_url)

        except etree.ParserError as e:
            logger.error("extract_next_links: Parser error for url " + resp.url + ": " + repr(e) + ".")

        return set(extracted_links), False


def is_valid(url):
    try:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            logger.debug(f"Invalid URL found: {url}. Scheme is not HTTP or HTTPS.")
            return False

        # Note: must be infix search to account for port numbers in net location.
        elif not re.match(r".*ics\.uci\.edu.*|.*cs\.uci\.edu.*|.*informatics\.uci\.edu.*|"
                          r".*stat\.uci\.edu.*", parsed.netloc.lower()) and \
                not (re.match(r".*today\.uci\.edu.*", parsed.netloc.lower()) and
                     re.match(r"/department/information_computer_sciences.*", parsed.path)):
            logger.debug(f"Invalid URL found: {url}. Not in valid set of domains.")
            return False

        elif re.match(
                r".*\.(css|js|bmp|gif|jpe?g|ico"
                + r"|png|tiff?|mid|mp2|mp3|mp4"
                + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
                + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
                + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
                + r"|epub|dll|cnf|tgz|sha1"
                + r"|thmx|mso|arff|rtf|jar|csv"
                + r"|rm|smil|wmv|swf|wma|zip|rar|gz)$", parsed.path.lower()):
            logger.debug(f"Invalid URL found: {url}. File type is invalid.")
            return False

        return True

    except TypeError as e:
        logger.error(f'Type error found for. {e}')
        raise
