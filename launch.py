from configparser import ConfigParser
from argparse import ArgumentParser

from utils.server_registration import get_cache_server
from utils.config import Config
from crawler import Crawler

import os


def main(config_file, restart):
    cparser = ConfigParser()
    cparser.read(config_file)
    config = Config(cparser)
    config.cache_server = get_cache_server(config, restart)

    # TODO: This is a dirty solution to delete our persistent files
    # defined in scraper.py. Is there a way to have the db filenames
    # accessible across this file and scraper.py in case we need to
    # rename them?
    if restart:
        for filename in ["common_words_table.db", "ics_subdomain_table.db", "common_words_table.db"]:
            if os.path.exists(filename):
                os.remove(filename)

    crawler = Crawler(config, restart)
    crawler.start()


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("--restart", action="store_true", default=False)
    parser.add_argument("--config_file", type=str, default="config.ini")
    args = parser.parse_args()
    main(args.config_file, args.restart)