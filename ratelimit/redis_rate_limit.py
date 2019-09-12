import time

from functools import wraps
from django.conf import settings
import redis
from .exceptions import RateLimited, DatastoreConnectionError

__author__ = 'vikaschahal'


class RateLimiter(object):
    """Base class for Rate Limiting"""

    def __init__(self, limit, window, connection, key):
        """
        :param limit: number of requests allowed
        :type limit: int
        :param window: window in secs in which :limit number requests allowed
        :type window: int
        """
        self._connection = connection
        self._key = key
        self._limit = limit
        self._window = window

    def is_allowed(self, log_current_request=True):
        """
        :param log_current_request: Consider the call for rate limiting
        :type log_current_request: bool
        :return: Whether a requests is allowed or rate limited.
        :rtype: bool
        """
        raise NotImplementedError

    @property
    def remaining_requests(self):
        raise NotImplementedError

    def limit(self, func):
        """Decorator to check the rate limit."""

        @wraps(func)
        def decorated(*args, **kwargs):
            if self.is_allowed():
                return func(*args, **kwargs)
            raise RateLimited

        return decorated


class RedisRateLimiterConnection(object):
    def __init__(self, host=None, port=None, db=0, connection=None):
        self.connection = None
        if host and port:
            connection = redis.StrictRedis(host, port, db)
            if not connection.ping():
                raise DatastoreConnectionError
            self.connection = connection
        elif connection:
            if not connection.ping():
                raise DatastoreConnectionError
            self.connection = connection
        else:
            raise DatastoreConnectionError


class RedisRateLimiter(RateLimiter):
    def __init__(self, limit, window, connection, key):
        super(RedisRateLimiter, self).__init__(limit, window, connection, key)
        self._pipeline = self._connection.connection.pipeline()

    def _increment_request(self):
        key_value = int(time.time()) + self._window
        self._pipeline.zadd(
            self._key, key_value, key_value
        )
        self._pipeline.expire(self._key, self._window) # set key expiry
        self._pipeline.execute()

    def is_allowed(self, log_current_request=True):
        if log_current_request:
            self._increment_request()
        current_time = time.time()
        self._pipeline.zremrangebyscore(self._key, '-inf', current_time)
        self._pipeline.zcount(self._key, '-inf', '+inf')
        result = self._pipeline.execute()
        return result[-1] <= self._limit

    def count(self, log_current_request=True):
        if log_current_request:
            self._increment_request()
        current_time = time.time()
        self._pipeline.zremrangebyscore(self._key, '-inf', current_time)
        self._pipeline.zcount(self._key, '-inf', '+inf')
        result = self._pipeline.execute()
        return result[-1]


class IpRateLimiter(RateLimiter):
    def __init__(self, limit, window, connection, key):
        super(IpRateLimiter, self).__init__(limit, window, connection, key)
        self.connection = self._connection.connection

    def add(self, value):
        self.connection.sadd(self._key, value)
        self.connection.expire(self._key, self._window)

    def count(self):
        return self.connection.scard(self._key)

    def delete(self):
        self.connection.delete(self._key)

    def is_allowed(self, log_current_request=True):
        if not self.connection.exists(self._key):
            return True
        if self.connection.ttl(self._key) < 0:
            self.delete()
            return True
        return self.count() < self._limit

    @property
    def remaining_requests(self):
        return self._limit - self.count()


redis_connection = RedisRateLimiterConnection(host=settings.REDIS_HOST_INTERNAL, port=6379, db=0)
