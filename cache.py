import threading
import time

from pickle import load, dump
from os.path import isfile

from dns import SUPPORTED_TYPES


def _init_cache(filename):
    if not isfile(filename):
        return {t: {} for t in SUPPORTED_TYPES}

    with open(filename, 'rb') as f:
        return load(f)


def _write_cache(cache, filename):
    with open(filename, 'wb') as f:
        dump(cache, f)


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
            to_delete = set()

            for kk, v in self.__cache.items():
                for k, record in v.items():
                    if current_time - record.creation_time > record.ttl:
                        to_delete.add((kk, v, k))

            for kk, v, k in to_delete:
                del self.__cache[(kk, v)][k]


class Record:
    def __init__(self, value, ttl, creation_time):
        self.value = value
        self.ttl = ttl
        self.creation_time = creation_time


class Cache:
    def __init__(self, filename):
        self.__filename = filename
        self.__cache = _init_cache(filename)
        self.__lock = threading.Lock()
        self.__cleaner = _CacheCleaner(self.__cache, self.__lock)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.__cleaner.stop()
        _write_cache(self.__cache, self.__filename)

    def get(self, type_, key) -> [Record, None]:
        with self.__lock:
            if type_ not in SUPPORTED_TYPES:
                raise ValueError(f'Unsupported type ({type_}) to use in cache')

            if key not in self.__cache[type_]:
                return None

            return self.__cache[type_][key]

    def put(self, type_, key, value, ttl):
        with self.__lock:
            if type_ not in SUPPORTED_TYPES:
                raise ValueError(f'Unsupported type ({type_}) to use in cache')

            self.__cache[type_][key] = Record(value, ttl, time.time())
