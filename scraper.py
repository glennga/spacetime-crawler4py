import re

from utils import get_logger
from urllib.parse import urlparse
from lxml import etree, html
import shelve


logger = get_logger('Scraper')
token_logger = get_logger('Token')


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
        with shelve.open("longest_page_stat.db") as db:
            self.longest_page_stat = (db["largest"][0], db["largest"][1]) if "largest" in db else ("", 0)
        #self.common_words_table = {}}
        #self.ics_subdomain_table = {}

    def handle_q1(self, url):
        pass  # This is to be handled offline (i.e. looking at the log files).

    def handle_q2(self, url, n):
        if n > self.longest_page_stat[1]:
            self.longest_page_stat = (url, n)
            logger.info(f'New longest page found: "{url}" with {n} words.')
            with shelve.open("longest_page_stat.db") as db:
                db["largest"] = self.longest_page_stat

    def handle_q3(self, tokens):
        with shelve.open("common_words_table.db") as db:
            # logger.info("Tokens: " + str(tokens))
            for token in tokens:
                if token and token not in db:
                    db[token] = 1
                    #logger.info(f'Found new token: {token}')
                elif token:
                    db[token] += 1
                    #logger.info(f'Incrementing token count for token: {token}')
            token_logger.info("Top 50 tokens at this stage: " + str(sorted(db.items(), key=lambda x: [-x[1], x[0]])[:50]))


    def handle_q4(self, url):
        # Note: we are assuming that unique URLs are being given here.
        with shelve.open("ics_subdomain_table.db") as db:
            parsed = urlparse(url)
            is_ics_subdomain = re.match(r".*\.ics.uci.edu.*", parsed.netloc)
            if is_ics_subdomain and parsed.netloc not in db:
                db[parsed.netloc] = 1
                logger.info(f'Found new subdomain for ics.uci.edu: {parsed.netloc}')
            elif is_ics_subdomain:
                db[parsed.netloc] += 1
                logger.info(f'Incrementing count for existing subdomain: {parsed.netloc}')


class _Enforcer:
    def enforce_before_crawl(self, resp) -> bool:
        # check for 200 here in resp
        # check for filesize here
        pass  # TODO

    def enforce_after_crawl(self, links) -> iter:
        pass  # TODO


tokenizer = _Tokenizer()
auditor = _Auditor()
enforcer = _Enforcer()


def scraper(url, resp):
    links = extract_next_links(url, resp)
    #return enforcer.enforce_after_crawl(links)
    return [link for link in links if is_valid(link)]


def extract_next_links(url, resp):
    # Implementation requred.
    # print("URL:     " + url)
    # print("RespURL: " + resp.url)
    # print("Status:  " + str(resp.status))
    # print("Error:   " + str(resp.error))
    # print(resp.raw_response)

    #if not enforcer.enforce_before_crawl(resp):
       #return []

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
