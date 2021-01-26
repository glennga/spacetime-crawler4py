import re
from urllib.parse import urlparse
from lxml import etree, html

def scraper(url, resp):
    links = extract_next_links(url, resp)
    return [link for link in links if is_valid(link)]

def extract_next_links(url, resp):
    # Implementation requred.
    print("URL:     " + url)
    print("RespURL: " + resp.url)
    print("Status:  " + str(resp.status))
    print("Error:   " + str(resp.error))
    #print(resp.raw_response)

    extracted_links = list()

    try:
        html_response = html.document_fromstring(resp.raw_response.content if resp.raw_response is not None else "")
        html_response.make_links_absolute(resp.url)
        html_response_links = [link for link in html_response.iterlinks() if link[0]]

        for link in html_response_links:
            if link[0].tag == "a" and link[1] == "href":
                extracted_links.append(link[2])
    except etree.ParserError as e:
        print("Parser Error for url " + resp.url + ": " + repr(e))

    print(extracted_links)
    return extracted_links

def is_valid(url):
    try:
        parsed = urlparse(url)
        if parsed.scheme not in set(["http", "https"]):
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
        print ("TypeError for ", parsed)
        raise