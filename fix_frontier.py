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

    def fix(self, file_name):
        removed_count = 0
        with open("./removed_urls.txt", "a") as removed_url_file:
            removed_url_file.write("===")
            with (shelve.open(file_name)) as db:
                # { hash : (url, complete)}
                for key, value in db.items():
                    # parsed = urlparse(db[key][0])
                    # filtered_url from extract_next_links() in scraper.py
                    filtered_url = value[0]
                    if not is_valid(filtered_url, self.config):
                        print("Found match to delete: " + filtered_url)
                        del db[key]
                        removed_count += 1
                        removed_url_file.write(value[0] + "\n")
                        # input("(enter to continue)")
            print("Removed " + str(removed_count) + " links from the frontier (saved in ./removed_urls.txt)")


def main(config_file, file_name):
    frontierFixer = FrontierFixer(config_file)
    frontierFixer.fix(file_name)


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("--db_file", type=str, default="./out/frontier.shelve")
    parser.add_argument("--config_file", type=str, default="config.ini")
    args = parser.parse_args()
    main(args.config_file, args.db_file)