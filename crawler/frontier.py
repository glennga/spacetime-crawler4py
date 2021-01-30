import os
import shelve

from threading import Thread, RLock
from queue import Queue, Empty

from utils import get_logger, get_urlhash, normalize
from scraper import is_valid

import random

class Frontier(object):
    def __init__(self, config, restart):
        self.logger = get_logger("Frontier")
        self.config = config
        self.to_be_downloaded = list()
        
        if not os.path.exists(self.config.save_file) and not restart:
            # Save file does not exist, but request to load save.
            self.logger.info(
                f"Did not find save file {self.config.save_file}, "
                f"starting from seed.")
        elif os.path.exists(self.config.save_file) and restart:
            # Save file does exists, but request to start from seed.
            self.logger.info(
                f"Found save file {self.config.save_file}, deleting it.")
            os.remove(self.config.save_file)
        # Load existing save file, or create one if it does not exist.
        self.save = shelve.open(self.config.save_file)
        if restart:
            for url in self.config.seed_urls:
                self.add_url(url)
        else:
            # Set the frontier state with contents of save file.
            self._parse_save_file()
            if not self.save:
                for url in self.config.seed_urls:
                    self.add_url(url)

    def _parse_save_file(self):
        ''' This function can be overridden for alternate saving techniques. '''
        total_count = len(self.save)
        tbd_count = 0
        for url, completed in self.save.values():
            if not completed and is_valid(url):
                self.to_be_downloaded.append(url)
                tbd_count += 1
        self.logger.info(
            f"Found {tbd_count} urls to be downloaded from {total_count} "
            f"total urls discovered.")

    def get_tbd_url(self):
        try:
            # TODO: Implement random restart.
            # This part can be kept separate for logging purposes.
            # I thought about implementing some sort of random shuffle
            # instead of using an occasional random pop mid-list.
            # For now, for complexity purposes, I'm sticking with
            # using a random number generator to randomly select
            # a link in the list but preserving the order. Hopefully,
            # that link provides more links to add to the FIFO queue.
            restart_threshold = 10
            restart_value = random.randrange(0,100)
            if (restart_value < restart_threshold):
                random_restart = True
                self.logger.info("Random restart triggered with <" + str(restart_threshold) + "% probability (" + str(restart_value) + "%)")
            else:
                random_restart = False
            return self.to_be_downloaded.pop(random.randrange(0,len(self.to_be_downloaded)) if random_restart else -1)
        except IndexError:
            return None

    def add_url(self, url):
        self.add_url_wrapper(url, False)

    # add_url_bypass skils the url hash check
    def add_url_force(self, url):
        self.add_url_wrapper(url, True)

    def add_url_wrapper(self, url, force):
        url = normalize(url)
        urlhash = get_urlhash(url)
        if force or urlhash not in self.save:
            self.save[urlhash] = (url, False)
            self.save.sync()
            self.to_be_downloaded.append(url)
    
    def mark_url_complete(self, url):
        urlhash = get_urlhash(url)
        if urlhash not in self.save:
            # This should not happen.
            self.logger.error(
                f"Completed url {url}, but have not seen it before.")

        self.save[urlhash] = (url, True)
        self.save.sync()
