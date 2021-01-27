import re
import shelve
import time

from utils import get_logger
from urllib.parse import urlparse
from lxml import etree, html
from utils.download import download
from urllib.robotparser import RobotFileParser

logger = get_logger('Scraper')
# TODO (GLENN): Replace the use of netloc w/ hostname.


class _Tokenizer:
    def __init__(self):
        self.stop_words = set(
            'a,able,about,across,after,all,almost,also,am,among,an,and,any,are,as,at,be,because,been,' \
            'but,by,can,cannot,could,dear,did,do,does,either,else,ever,every,for,from,get,got,had,has,' \
            'have,he,her,hers,him,his,how,however,i,if,in,into,is,it,its,just,least,let,like,likely,' \
            'may,me,might,most,must,my,neither,no,nor,not,of,off,often,on,only,or,other,our,own,rather,' \
            'said,say,says,she,should,since,so,some,than,that,the,their,them,then,there,these,they,' \
            'this,tis,to,too,twas,us,wants,was,we,were,what,when,where,which,while,who,whom,why,will,' \
            'with,would,yet,you,your'.split(',')
        )

    def tokenize_page(self, page_text):
        """ :return: a) the length of the page in terms of tokens, and b) a set of non-stop word tokens. """
        root = html.fromstring(page_text)
        text_body = ''
        for element in root.iter():
            # Conditions: a) text must be not null, b) the element must have a 'simple' tag, and c) the element tag
            # must not be a script or a style tag.
            if element.text is not None and type(element.tag) == str and \
                    element.tag != 'script' and element.tag != 'style':
                text_body += element.text

        non_stopped_tokens = [t.lower() for t in re.split(r"[^a-zA-Z]+", text_body) if len(t) > 0]
        return len(non_stopped_tokens), set([t for t in non_stopped_tokens if t not in self.stop_words])


class _Auditor:
    def __init__(self):
        self.longest_page_stat = ('', 0)
        self.common_words_table = {}
        self.ics_subdomain_table = {}

    def handle_q1(self, url):
        pass  # This is to be handled offline (i.e. looking at the log files).

    def handle_q2(self, url, n):
        if n > self.longest_page_stat[1]:
            self.longest_page_stat = (url, n)
            logger.info(f'New longest page found: "{url}" with {n} words.')

    def handle_q3(self, tokens):
        # TODO: Finish this case, log each time a new entry is added to the common words table.
        # logger.info("Tokens: " + str(tokens))
        for token in tokens:
            if token and token not in self.common_words_table:
                self.common_words_table[token] = 1
                #logger.info(f'Found new token: {token}')
            elif token:
                self.common_words_table[token] += 1
                #logger.info(f'Incrementing token count for token: {token}')
        #logger.info("Top 50 tokens at this stage: " + str(sorted(self.common_words_table.items(), key=lambda x: [-x[1], x[0]])[:50]))

    def handle_q4(self, url):
        # Note: we are assuming that unique URLs are being given here.
        parsed = urlparse(url)

        is_ics_subdomain = re.match(r".*\.ics.uci.edu.*", parsed.netloc)
        if is_ics_subdomain and parsed.netloc not in self.ics_subdomain_table:
            self.ics_subdomain_table[parsed.netloc] = 1
            logger.info(f'Found new subdomain for ics.uci.edu: {parsed.netloc}')
        elif is_ics_subdomain:
            self.ics_subdomain_table[parsed.netloc] += 1
            logger.info(f'Incrementing count for existing subdomain: {parsed.netloc}')


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

    def __init__(self):
        self.large_page_threshold_bytes = 1.0e8
        self.robots_table = shelve.open('robots.shelve')
        self.robots_parser = RobotFileParser()
        self.config = None

        logger.info(f"Setting large page threshold to be: {self.large_page_threshold_bytes} bytes.")

    def reset(self, config):
        self.config = config

    def enforce_before_crawl(self, url, resp) -> bool:
        if resp.status != 200:
            logger.warn(f"Page found w/ non-200 status code: {url}")
            return False

        elif len(resp.raw_response.content) > self.large_page_threshold_bytes:
            logger.warn(f"Page found w/ size greater than large page threshold: {url} of size "
                        f"{len(resp.raw_response.content)} bytes.")
            return False

        return True

    def _fetch_robots(self, parsed) -> float:
        """ Time in seconds that indicates **additional** time to wait, based on the URL's robots.txt file. """
        time.sleep(self.config.time_delay)
        robots_url = parsed.scheme + '://' + parsed.netloc + '/robots.txt'
        resp = download(robots_url, self.config, logger)
        if resp.status != 200:
            logger.warn(f'Could not find robots.txt file for site {robots_url}.')
            return 0
        else:
            for line in resp.raw_response.text.split('\n'):
                if 'crawl-delay' in line:  # Crawl delays are in seconds.
                    crawl_delay_s = float(line.split(':')[1].strip())
                    logger.info(f'crawl-delay found for site {robots_url} of {crawl_delay_s} seconds.')
                    return max(crawl_delay_s, self.config.time_delay) - self.config.time_delay

            logger.info(f'Could not find crawl-delay in robots.txt file for site {robots_url}. Using default '
                        f'delay of {self.config.time_delay} seconds.')
            return 0

    def enforce_after_crawl(self, links) -> iter:
        enforced_links = _Enforcer.URLIterable()
        for link in links:
            parsed = urlparse(link)
            if parsed.netloc not in self.robots_table:
                self.robots_table[parsed.netloc] = self._fetch_robots(parsed)

            if not is_valid(link):
                continue

            elif True:  # TODO: add the checks for infinite traps and sets of similar pages w/ no information.
                enforced_links.append_url(link, self.robots_table[parsed.netloc])

        return enforced_links


tokenizer = _Tokenizer()
auditor = _Auditor()
enforcer = _Enforcer()


def scraper(url, resp, config):
    enforcer.reset(config)
    links = extract_next_links(url, resp)
    return enforcer.enforce_after_crawl(links)


def extract_next_links(url, resp):
    # Implementation requred.
    # print("URL:     " + url)
    # print("RespURL: " + resp.url)
    # print("Status:  " + str(resp.status))
    # print("Error:   " + str(resp.error))
    # print(resp.raw_response)

    if not enforcer.enforce_before_crawl(url, resp):
        return []

    # Walk the page tree once to collect statistics on the page.
    word_count, tokens = tokenizer.tokenize_page(resp.raw_response.text)
    auditor.handle_q2(url, word_count)
    auditor.handle_q3(tokens)
    auditor.handle_q4(url)

    # Walk the page tree again to collect links.
    extracted_links = list()
    try:
        html_response = html.document_fromstring(resp.raw_response.content if resp.raw_response is not None else "")
        html_response.make_links_absolute(resp.url)
        html_response_links = [link for link in html_response.iterlinks() if link[0]]

        for link in html_response_links:
            if link[0].tag == "a" and link[1] == "href":
                parsed = urlparse(link[2])
                # Separated the filtered url parsing in case we need to log this
                filtered_url = (parsed.scheme + "://" + parsed.netloc + parsed.path
                                       # TODO: Do we keep the params and query?
                                       + ((";" + parsed.params) if len(parsed.params) > 0 else "")
                                       + (("?" + parsed.query) if len(parsed.query) > 0 else "")
                                       )
                #logger.info("Filtered URL: " + filtered_url)
                extracted_links.append(filtered_url)
    except etree.ParserError as e:
        logger.error("Parser Error for url " + resp.url + ": " + repr(e))

    logger.info(f'Returning the following extracted links: {extracted_links}')
    return extracted_links


def is_valid(url):
    try:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            return False

        # Note: must be infix search to account for port numbers in net location.
        elif not re.match(r".*\.ics.uci.edu.*|.*\.cs.uci.edu.*|.*\.informatics.uci.edu.*|"
                          r".*\.stat.uci.edu.*", parsed.netloc) and \
                not (re.match(r".*\.today.uci.edu.*", parsed.netloc) and
                     re.match(r"/department/information_computer_sciences.*", parsed.path)):
            return False

        return not re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            + r"|png|tiff?|mid|mp2|mp3|mp4"
            + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
            + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
            + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            + r"|epub|dll|cnf|tgz|sha1"
            + r"|thmx|mso|arff|rtf|jar|csv"
            + r"|rm|smil|wmv|swf|wma|zip|rar|gz)$", parsed.path.lower())

    except TypeError:
        print("TypeError for ", parsed)
        raise
