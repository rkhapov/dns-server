import threading
import time
from os.path import isfile
from pickle import load, dump
from typing import List, Dict

from dns import SUPPORTED_TYPES


class Record:
    def __init__(self, value, ttl, creation_time):
        self.value = value
        self.ttl = ttl
        self.creation_time = creation_time


def _init_cache(filename) -> Dict[int, Dict[str, List[Record]]]:
    if not isfile(filename):
        return {t: {} for t in SUPPORTED_TYPES}

    with open(filename, 'rb') as f:
        return load(f)


def _write_cache(cache, filename):
    with open(filename, 'wb') as f:
        dump(cache, f)


# structure of the cache:
# { type -> {requested string -> list of Record} }


class _CacheCleaner(threading.Thread):
    def __init__(self, cache, lock):
        super().__init__()
        self.__cache = cache
        self.__stopped = False
        self.__lock = lock

    def run(self):
        while not self.__stopped:
            self._run_cleaning()
            time.sleep(2)

    def stop(self):
        self.__stopped = True

    def _run_cleaning(self):
        with self.__lock:
            current_time = time.time()

            for type_, request_to_list in self.__cache.items():
                requests_to_delete = []

                for request, records in request_to_list.items():
                    expired_indexes = []

                    for i, record in enumerate(records):
                        if current_time - record.creation_time > record.ttl:
                            expired_indexes.append(i)

                    for i in sorted(expired_indexes, reverse=True):
                        del records[i]

                    if len(records) == 0:
                        requests_to_delete.append(request)

                for request in requests_to_delete:
                    del request_to_list[request]


class Cache:
    def __init__(self, filename):
        self.__filename = filename
        self.__cache = _init_cache(filename)
        self.__lock = threading.Lock()
        self.__cleaner = _CacheCleaner(self.__cache, self.__lock)
        self.__cleaner.start()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.__cleaner.stop()
        _write_cache(self.__cache, self.__filename)

    def get(self, type_, key) -> [List[Record], None]:
        with self.__lock:
            if type_ not in SUPPORTED_TYPES:
                raise ValueError(f'Unsupported type ({type_}) to use in cache')

            if key not in self.__cache[type_]:
                return None

            return self.__cache[type_][key]

    def put(self, type_, key, ttl, *values):
        with self.__lock:
            if type_ not in SUPPORTED_TYPES:
                raise ValueError(f'Unsupported type ({type_}) to use in cache')

            if key not in self.__cache[type_]:
                self.__cache[type_][key] = list()

            current_time = time.time()

            for value in values:
                record = Record(value, ttl, current_time)
                self.__cache[type_][key].append(record)
