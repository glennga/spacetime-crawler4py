from configparser import ConfigParser
from argparse import ArgumentParser
from utils.config import Config
from scraper import is_valid

from urllib.parse import urlparse, urljoin

import shelve
import re


class FrontierFixer:
    def __init__(self, config_file):
        cparser = ConfigParser()
        cparser.read(config_file)
        self.config = Config(cparser)
        self.avoid_urls = self.config.avoid_urls

    def fix_frontier(self, frontier_file, force_delete):
        print("fix_frontier_file")
        removed_count = 0
        with open("./removed_urls_frontier.txt", "a") as removed_url_file:
            removed_url_file.write("==="+frontier_file+"===\n")
            with (shelve.open(frontier_file)) as db:
                # { hash : (url, complete)}
                for key, value in db.items():
                    # parsed = urlparse(db[key][0])
                    # filtered_url from extract_next_links() in scraper.py
                    filtered_url = value[0]
                    if not is_valid(filtered_url, self.config):
                        print("Found match to delete: " + filtered_url)
                        if force_delete:
                            del db[key]
                        removed_count += 1
                        removed_url_file.write(value[0] + "\n")
                        # input("(enter to continue)")
            print("" + ("" if force_delete else "(Preview) ") + "Removed " + str(removed_count) + " links from the frontier (saved in ./removed_urls_frontier.txt)")

    def fix_token_hash(self, tokens_file, force_delete):
        print("fix_token_hash")
        removed_count = 0
        with open("./removed_urls_tokenhash.txt", "a") as removed_url_file:
            removed_url_file.write("==="+tokens_file+"===\n")
            with (shelve.open(tokens_file)) as db:
                # { hash : (url, complete)}
                for key, value in db.items():
                    # parsed = urlparse(db[key][0])
                    # filtered_url from extract_next_links() in scraper.py
                    filtered_url = value
                    if not is_valid(filtered_url, self.config):
                        print("Found match to delete: " + filtered_url)
                        if force_delete:
                            del db[key]
                        removed_count += 1
                        removed_url_file.write(value[0] + "\n")
                        # input("(enter to continue)")
            print("" + ("" if force_delete else "(Preview) ") + "Removed " + str(removed_count) + " links from the tokenhash (saved in ./removed_urls_tokenhash.txt)")


def main(config_file, frontier_file, tokens_file, force_delete):
    frontierFixer = FrontierFixer(config_file)
    frontierFixer.fix_frontier(frontier_file, force_delete)
    frontierFixer.fix_token_hash(tokens_file, force_delete)



if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("--frontier_file", type=str, default="./out/frontier.shelve")
    parser.add_argument("--tokens_file", type=str, default="./out/token_hash.shelve")
    parser.add_argument("--config_file", type=str, default="config.ini")
    parser.add_argument("--force_delete", type=bool, default=False)
    args = parser.parse_args()
    main(args.config_file, args.frontier_file, args.tokens_file, args.force_delete)