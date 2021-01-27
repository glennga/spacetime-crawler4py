import shelve

class DBViewer:
    def __init__(self):
        self.longest_page_stat = "longest_page_stat.db"
        self.common_words_table = "common_words_table.db"
        self.ics_subdomain_table = "ics_subdomain_table.db"

    def print_longest_page_stat(self):
        self.print_database(self.longest_page_stat)

    def print_common_words_table(self):
        self.print_database(self.common_words_table)

    def print_ics_subdomain_table(self):
        self.print_database(self.ics_subdomain_table)

    def print_database(self, file_name):
        print(file_name)
        with (shelve.open(file_name)) as db:
            for key, value in (sorted(db.items(), key=lambda x: (-1 * int(x[1]) if type(x[1]) is not tuple else x[1], x[0]))[:min(len(db), 50)]):
                print(key + ": " + str(value))

if __name__ == "__main__":
    dbviewer = DBViewer()
    print("===")
    dbviewer.print_ics_subdomain_table()
    print("===")
    dbviewer.print_common_words_table()
    print("===")
    dbviewer.print_longest_page_stat()