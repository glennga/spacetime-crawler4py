import re


class Config(object):
    def __init__(self, config):
        self.user_agent = config["IDENTIFICATION"]["USERAGENT"].strip()
        print (self.user_agent)
        assert self.user_agent != "DEFAULT AGENT", "Set useragent in config.ini"
        assert re.match(r"^[a-zA-Z0-9_ ,]+$", self.user_agent), "User agent should not have any special characters outside '_', ',' and 'space'"
        self.threads_count = int(config["LOCAL PROPERTIES"]["THREADCOUNT"])
        self.save_file = config["LOCAL PROPERTIES"]["SAVE"]

        # Files pertaining to our scraper.
        self.longest_page_file = config["LOCAL PROPERTIES"]["LONGESTPAGE"]
        self.common_words_file = config["LOCAL PROPERTIES"]["COMMONWORDS"]
        self.ics_subdomain_file = config["LOCAL PROPERTIES"]["ICSSUBDOMAIN"]
        self.robots_file = config["LOCAL PROPERTIES"]["ROBOTS"]
        self.tokens_file = config["LOCAL PROPERTIES"]["TOKENHASH"]

        self.host = config["CONNECTION"]["HOST"]
        self.port = int(config["CONNECTION"]["PORT"])

        self.seed_urls = config["CRAWLER"]["SEEDURL"].split(",")
        self.avoid_urls = config["CRAWLER"]["AVOIDURL"].split(",")
        self.time_delay = float(config["CRAWLER"]["POLITENESS"])

        self.cache_server = None

    def get_scraper_files(self):
        """ :return All files used by our scraper. """
        return [self.longest_page_file, self.common_words_file, self.ics_subdomain_file, self.robots_file,
                self.tokens_file]