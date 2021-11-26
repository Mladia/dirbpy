#!/usr/bin/env python3

# -*- coding: utf-8 -*-


import glob
import logging
import requests
import sys
import argparse
import xml.etree.ElementTree as ET

from logging import Logger
from urllib.parse import urljoin, urlparse
#do not use Threads for now
# from multiprocessing.dummy import Pool as ThreadPool

# def disable_https_warnings():
#     import urllib3
#     urllib3.disable_warnings()

class URLBruteforcer():
    HTTPS_STR = 'https'
    HTTP_STR = 'http'
    MAX_NUMBER_REQUEST = 30
    VALID_STATUS_CODE = [200, 201, 202, 203, 301, 302, 400, 401, 403, 405, 500, 503]
    DIRECTORY_FOUND_MESSAGE = 'Directory => {} (Status code: {})'
    URL_FOUND_MESSAGE = '{} (Status code: {})'
    SCANNING_URL_MESSAGE = 'Scanning URL: {}'
    PROXY_DEFAULT_DICT = {HTTPS_STR: None, HTTP_STR: None}

    def __init__(self, host:            str,
                 word_dictionary:       list,
                 nb_thread:             int    = MAX_NUMBER_REQUEST,
                 status_code:           list   = VALID_STATUS_CODE,
                 proxy:                 dict   = PROXY_DEFAULT_DICT,
                 directories_to_ignore: list   = [],
                 logger:                Logger = logging.getLogger(__name__),
                 duplicate_log:         bool   = True):

        self.host = host
        # if 'https' in urlparse(self.host).scheme:
        #     disable_https_warnings()
        self.word_dictionary = word_dictionary
        self.status_code = status_code
        # self.nb_thread = nb_thread
        # self.request_pool = ThreadPool(self.nb_thread)

        if proxy == self.PROXY_DEFAULT_DICT:
            self.proxy = proxy
        else:
            self.proxy = self.PROXY_DEFAULT_DICT
            self.proxy[self.HTTPS_STR] = self._url_to_https(proxy)
            self.proxy[self.HTTP_STR] = self._url_to_http(proxy)

        self.directories_to_ignore = directories_to_ignore
        self.logger = logger
        if not duplicate_log:
            self.logged_message = []
            self.logger.addFilter(self.no_duplicate_log_filter)

        # print("Brute forces inited")

    def no_duplicate_log_filter(self, record) -> bool:
        if record.msg not in self.logged_message:
            self.logged_message.append(record.msg)
            return True
        return False

    def send_requests_with_all_words(self, url: str = None) -> None:
        url = url or self.host
        self.logger.info(self.SCANNING_URL_MESSAGE.format(url))
        print("Sending request with all words to " + str(url))

        url_completed = self._generate_complete_url_with_word(url)
        # directories_found = self.request_pool.map(self._request_thread, url_completed)
        # directories_found = self._request_thread(url_completed)
        for _url in url_completed:
            directories_found = self._perfrom_request(_url);

        flat_list_of_directories = self._generate_fat_list_with_list_of_list(directories_found)
        dir_filtered = self._remove_invalid_url_from_directory_found(flat_list_of_directories, url)
        for directory in dir_filtered:
            if not self._is_directory_to_ignore(directory):
                self.send_requests_with_all_words(directory)

    def _url_to_https(self, url: str) -> str:
        return url.replace(self.HTTP_STR, self.HTTPS_STR)

    def _url_to_http(self, url: str) -> str:
        return url.replace(self.HTTPS_STR, self.HTTP_STR)
   
    def _generate_fat_list_with_list_of_list(self, list_of_list: list) -> list:
        return [item for sublist in list_of_list for item in sublist]

    def _generate_complete_url_with_word(self, url: str) -> list:
        return [urljoin(url, word) for word in self.word_dictionary if word not in ('/', '')]

    def _is_directory_to_ignore(self, directory: str) -> bool:
        directory_found_to_ignore = [True for directory_to_ignore in self.directories_to_ignore 
                                     if directory_to_ignore in urlparse(directory).path]
        return True if any(directory_found_to_ignore) else False

    def _remove_invalid_url_from_directory_found(self, directories_found: list, url: str) -> list:
        return [dir_to_test for dir_to_test in directories_found 
                if dir_to_test is not None and dir_to_test != url]

    def _request_thread(self, complete_url: str) -> list:
        #Perfrom request from thread
        print("Perfrom request to " + complete_url)
        try:
            response = requests.get(complete_url, proxies=self.proxy, verify=False)
        except requests.exceptions.ConnectionError:
            self.logger.warning("Connection refused: " + complete_url)
            return []
        except Exception as e:
            self.logger.error(str(e) + '. URL: {}'.format(complete_url), exc_info=True)
            return []
        else:
            return self._analyse_response(response)
            
    def _perfrom_request(self, complete_url: str) -> list:
        #Perfrom request from thread
        print("Perfrom request " + complete_url)
        try:
            response = requests.get(complete_url, proxies=self.proxy, verify=False)
        except requests.exceptions.ConnectionError:
            self.logger.warning("Connection refused: " + complete_url)
            return []
        except Exception as e:
            self.logger.error(str(e) + '. URL: {}'.format(complete_url), exc_info=True)
            return []
        else:
            return self._analyse_response(response)


    def _response_has_valid_status_code(self, response) -> bool:
        return response.status_code in self.status_code

    def _analyse_response(self, response) -> list:
        directories_url_found = []
        if self._response_has_valid_status_code(response):
            # We need to check for redirection, if we are redirected we want the first url
            # Normaly get redirected it returns a 200 status_code but it not always the real status code
            if response.history:
                for response_in_history in response.history:
                    # Check if it's the same path
                    response_removed_url = response.url.replace(response_in_history.url, '')
                    if response_removed_url == '/':
                        self.logger.info(self.DIRECTORY_FOUND_MESSAGE.format(response.url, str(response.status_code)))
                        directories_url_found.append(response.url)
                    else:
                        # Sometimes the response contains invalid status code
                        if self._response_has_valid_status_code(response_in_history):
                            self.logger.info(self.URL_FOUND_MESSAGE.format(response_in_history.url, str(response_in_history.status_code)))

            # Analyse the response if we didn't print it earlier
            if response.url not in directories_url_found:
                if response.url.endswith('/'): 
                    self.logger.info(self.DIRECTORY_FOUND_MESSAGE.format(response.url, str(response.status_code)))
                    directories_url_found.append(response.url)
                else:
                    self.logger.info(self.URL_FOUND_MESSAGE.format(response.url, str(response.status_code)))
        elif response.status_code == 404:
            # We need to check for redirection if we are redirected we want the first url
            # Normaly when we find a directory like /css/ it returns a 404
            if response.history and response.history[0].status_code in self.status_code:
                if response.url.endswith('/'):
                    self.logger.info(self.DIRECTORY_FOUND_MESSAGE.format(response.url, str(response.history[0].status_code)))
                    directories_url_found.append(response.url)
        return directories_url_found





#WordDictiornary


class WordDictonary():

    def __init__(self, file_word_dict):
        self.words = file_word_dict.readlines()
        self.current_index = 0

    def __len__(self) -> int:
        return len(self.words)

    def __iter__(self):
        self.current_index = 0
        return self

    def __next__(self) -> str:
        if self.current_index == len(self.words):
            raise StopIteration
        value = self.words[self.current_index]
        self.current_index += 1
        return value.rstrip()



###main

NUMBER_OF_THREAD_PARAMETER_ERROR = 'The number of thread is to high. Current: {}, Max: {}'
GENERATED_WORD_MESSAGE = "Generated words: {}"

FORMAT = '[%(asctime)s] [%(levelname)s] %(message)s'
logging.basicConfig(format=FORMAT, level=logging.INFO)
ROOT_LOGGER = logging.getLogger()


def remove_none_value_in_kwargs(params_dict: dict) -> dict:
    return {k: v for k, v in params_dict.items() if v is not None}


def do_request_with_online_file(dict_url: str, host: str, **kwargs) -> None:
    data = requests.get(dict_url)
    dict_list = str(data.content).replace('\\r', ' ').replace('\\n', ' ').split()
    use_url_bruteforcer(dict_list, host, **kwargs)


def do_request_with_dictionary(file_dict, host: str, **kwargs) -> None:
    word_dictionary = WordDictonary(file_dict)
    use_url_bruteforcer(word_dictionary, host, **kwargs)


def use_url_bruteforcer(words: list, host: str, **kwargs) -> None:
    params = remove_none_value_in_kwargs(kwargs) 
    ROOT_LOGGER.info(GENERATED_WORD_MESSAGE.format(len(words)))
    request_handler = URLBruteforcer(host, words, **params)
    request_handler.send_requests_with_all_words()


def number_of_thread(value: int) -> int:
    value = int(value)
    if value > URLBruteforcer.MAX_NUMBER_REQUEST:
        raise argparse.ArgumentTypeError(NUMBER_OF_THREAD_PARAMETER_ERROR.format(value, URLBruteforcer.MAX_NUMBER_REQUEST))
    return value


def get_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--url',
                        type=str,
                        help='This is the url to scan')
    parser.add_argument('-f', '--file',
                        type=str,
                        help='Input file with words.')
    parser.add_argument('-o', '--online',
                        type=str,
                        help='URL with raw dictionary')
    parser.add_argument('-d', '--directory',
                        type=str,
                        help='Input directory with dictionaries (.txt).')
    parser.add_argument('-t', '--thread',
                        type=number_of_thread,
                        help='Threads are disabled :( Number of thread, the max value is {}'.format(URLBruteforcer.MAX_NUMBER_REQUEST))
    parser.add_argument('-c', '--status-code',
                        nargs='*',
                        type=int,
                        help='Status codes list to accept, the default list is: {}'.format(URLBruteforcer.VALID_STATUS_CODE))
    parser.add_argument('-r', '--remove-status-code',
                        nargs='*',
                        type=int,
                        help='Status codes list to remove from original list')
    parser.add_argument('-p', '--proxy',
                        nargs='*',
                        type=str,
                        help='Specify the url of the proxy if you want to use one. (Ex: localhost:8080)')
    parser.add_argument('-i', '--ignore',
                        nargs='*',
                        type=str,
                        help='Ignore a directory (Ex: css images)')
    parser.add_argument('-v', '--version',
                        action='version',
                        # version='%(prog)s {version}'.format(version=__version__)
                        version='0.1'
                        )
    parser.add_argument('--no-duplicate',
                        action='store_false',
                        help='Don\'t display duplicate logs')
    parser.add_argument('-s', '--save',
                        type=str,
                        help='Output file.')
    parser.add_argument('--hosts-file',
                        type=argparse.FileType('r'),
                        help='File with urls to scan')
    #TODO:
    parser.add_argument('-n', '--nmap-file',
                        type=str,
                        help='Take as input an xml formatted name of file with nmap output generated with "nmap -n -oX nmap_output.xml -p-" ')

    return parser


def get_parsed_args(parser, args):
    args_parsed = parser.parse_args(args)

    if not args_parsed.directory and not args_parsed.file and not args_parsed.online:
        parser.error('Need a file (-f/--file) or a directory (-d/--directory) or an online file (-o/--online) as input.')

    if not args_parsed.url and not args_parsed.hosts_file:
        parser.error('Need an url (-u/--url) or a hosts file (--hosts_file)')

    return args_parsed


def read_nmap_xml(nmap_output_filename) -> list:
    print("Parsing " + nmap_output_filename)
    root = ET.parse(nmap_output_filename).getroot()
    nmap_ips = []
    for child in root:
        if child.tag == "host":
            status = child[0].attrib["state"]
            assert status =="up"
            ports = []
            address = child[1].attrib["addr"]
            for port in child[3][1:]:
                _port = port.attrib["portid"]
                ports.append(_port)
                nmap_ips.append("http://" + address + ":" + _port)
    # print(nmap_ips)
    return nmap_ips




def main():
    # print(DIRBPY_COOL_LOOKING)
    # print('Author: {}'.format(__author__))
    # print('Version: {}\n'.format(__version__))
   
    parser = get_parser()
    args = get_parsed_args(parser, sys.argv[1:])

    # print(args)

    if args.proxy:
        proxy = args.proxy[0]
        print(f'Using proxy: {proxy}\n')
    else:
        proxy = None

    status_code = None
    if args.status_code:
        status_code = args.status_code
    if args.remove_status_code:
        status_code = [code for code in URLBruteforcer.VALID_STATUS_CODE if code not in args.remove_status_code]

    directories_to_ignore = args.ignore
    dict_url = None
    if args.online:
        dict_url = args.online

    params = {
              "nb_thread": args.thread,
              "status_code": status_code,
              "proxy": proxy,
              "directories_to_ignore": directories_to_ignore,
              "duplicate_log": args.no_duplicate
             }

    if args.save:
        #TODO: JSON Output?
        # logging.error("Saving output...? no JSONFormatter...  ")
        file_handler = logging.FileHandler(args.save)
        # formatter = FileJSONFormatter()
        # file_handler.setFormatter(formatter)
        ROOT_LOGGER.addHandler(file_handler)
    


    hosts = []
    if args.hosts_file:
        hosts = args.hosts_file.readlines()
        hosts = [host.rstrip('\n') for host in hosts]

    if args.nmap_file:
        nmap_input = read_nmap_xml(args.nmap_file)
        print(nmap_input)
        hosts = nmap_input

    print("Done parsing parameters")
    for host in hosts or [args.url]:
        print("For every host")
        if args.directory:
            for file in glob.glob("{}*.txt".format(args.directory if args.directory.endswith('/') else args.directory + '/')):
                ROOT_LOGGER.info('Current file: {}'.format(file))
                with open(file, 'r') as opened_file:
                    do_request_with_dictionary(opened_file, host, **params) 
        elif dict_url:
            do_request_with_online_file(dict_url, host, **params)
        else:
            print("Doing request with opened file")
            with open(args.file, 'r') as opened_file:
                do_request_with_dictionary(opened_file, host, **params)



if __name__ == "__main__":
    main()

