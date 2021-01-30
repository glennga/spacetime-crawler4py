from configparser import ConfigParser
from argparse import ArgumentParser
from utils.config import Config

import shelve


class DBViewer:
    def __init__(self, config_file):
        cparser = ConfigParser()
        cparser.read(config_file)
        config = Config(cparser)
        self.longest_page_file = config.longest_page_file
        self.common_words_file = config.common_words_file
        self.ics_subdomain_file = config.ics_subdomain_file
        self.robots_file = config.robots_file

    def print_longest_page_file(self):
        self.print_database(self.longest_page_file)

    def print_common_words_file(self):
        self.print_database(self.common_words_file)

    def print_ics_subdomain_file(self):
        self.print_database(self.ics_subdomain_file)

    def print_robots(self):
        self.print_database(self.robots_file)

    def print_database(self, file_name):
        print(file_name)
        with (shelve.open(file_name)) as db:
            for key, value in (
            sorted(db.items(), key=lambda x: (-1 * int(x[1]) if type(x[1]) is not tuple else x[1], x[0]))[
            :min(len(db), 50)]):
                print(key + ": " + str(value))


def main(config_file, db_file):
    if len(db_file) > 0:
        print("===")
        DBViewer.print_database(None, db_file)
    else:
        dbviewer = DBViewer(config_file)
        print("===")
        dbviewer.print_ics_subdomain_file()
        print("===")
        dbviewer.print_common_words_file()
        print("===")
        dbviewer.print_robots()
        print("===")
        dbviewer.print_longest_page_file()


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("--config_file", type=str, default="config.ini")
    parser.add_argument("--db_file", type=str, default="")
    args = parser.parse_args()
    main(args.config_file, args.db_file)


