import hashlib
import json
import re
import time
import zlib
from importlib import import_module

from django.conf import settings
from django.core.cache import caches
from django.core.exceptions import ImproperlyConfigured

from redis_rate_limit import redis_connection, RedisRateLimiter, IpRateLimiter

from ratelimit import ALL, UNSAFE

__all__ = ['is_ratelimited', 'unblock_ip', 'block_ip', 'is_request_allowed']

_PERIODS = {
    's': 1,
    'm': 60,
    'h': 60 * 60,
    'd': 24 * 60 * 60,
}

# Extend the expiration time by a few seconds to avoid misses.
EXPIRATION_FUDGE = 5


def user_or_ip(request):
    if is_authenticated(request.user):
        return str(request.user.pk)
    return request.META['HTTP_X_FORWARDED_FOR']


_SIMPLE_KEYS = {
    'ip': lambda r: r.META['HTTP_X_FORWARDED_FOR'],
    'user': lambda r: str(r.user.pk),
    'user_or_ip': user_or_ip,
}


def get_header(request, header):
    key = 'HTTP_' + header.replace('-', '_').upper()
    return request.META.get(key, '')


_ACCESSOR_KEYS = {
    'get': lambda r, k: r.GET.get(k, ''),
    'post': lambda r, k: r.POST.get(k, ''),
    'header': get_header,
}


def _method_match(request, method=ALL):
    if method == ALL:
        return True
    if not isinstance(method, (list, tuple)):
        method = [method]
    return request.method in [m.upper() for m in method]


rate_re = re.compile('([\d]+)/([\d]*)([smhd])?')


def _split_rate(rate):
    if isinstance(rate, tuple):
        return rate
    count, multi, period = rate_re.match(rate).groups()
    count = int(count)
    if not period:
        period = 's'
    seconds = _PERIODS[period.lower()]
    if multi:
        seconds = seconds * int(multi)
    return count, seconds


def _get_window(value, period):
    ts = int(time.time())
    if period == 1:
        return ts
    if not isinstance(value, bytes):
        value = value.encode('utf-8')
    w = ts - (ts % period) + (zlib.crc32(value) % period)
    if w < ts:
        return w + period
    return w


def _make_cache_key(group, rate, value, methods, sliding_window=False):
    count, period = _split_rate(rate)
    safe_rate = '%d/%ds' % (count, period)
    if sliding_window:
        window = ''
    else:
        window = _get_window(value, period)
    parts = [group + safe_rate, value, str(window)]
    if methods is not None:
        if methods == ALL:
            methods = ''
        elif isinstance(methods, (list, tuple)):
            methods = ''.join(sorted([m.upper() for m in methods]))
        parts.append(methods)
    prefix = getattr(settings, 'RATELIMIT_CACHE_PREFIX', 'rl:')
    return prefix + hashlib.md5(u''.join(parts).encode('utf-8')).hexdigest()


def _get_value_from_key(request, group=None, key=None):
    if not key:
        raise ImproperlyConfigured('Ratelimit key must be specified')
    if callable(key):
        value = key(group, request)
    elif key in _SIMPLE_KEYS:
        print(_SIMPLE_KEYS[key](request))
        value = _SIMPLE_KEYS[key](request)
    elif ':' in key:
        accessor, k = key.split(':', 1)
        if accessor not in _ACCESSOR_KEYS:
            raise ImproperlyConfigured('Unknown ratelimit key: %s' % key)
        value = _ACCESSOR_KEYS[accessor](request, k)
    elif '.' in key:
        mod, attr = key.rsplit('.', 1)
        keyfn = getattr(import_module(mod), attr)
        value = keyfn(group, request)
    else:
        raise ImproperlyConfigured(
            'Could not understand ratelimit key: %s' % key)
    return value


def _get_usage_count(request, group=None, fn=None, key=None, rate=None,
                     method=ALL, increment=False, reset=None, sliding_window=True):
    value = _get_value_from_key(request, group=group, key=key)
    limit, period = _split_rate(rate)
    cache_key = _make_cache_key(group, rate, value, method, sliding_window)
    redis_limiter = RedisRateLimiter(limit=limit, window=period, connection=redis_connection, key=cache_key)
    count = redis_limiter.count()
    return {'count': count, 'limit': limit}


def get_offence_count(request, group=None, max_offence_rate=None,
                      key=None, method=ALL, sliding_window=True, count_current_request=False):
    value = _get_value_from_key(request, group=group, key=key)
    limit, period = _split_rate(max_offence_rate)
    cache_key = _make_cache_key(group, max_offence_rate, value, method, sliding_window)
    redis_limiter = RedisRateLimiter(limit=limit, window=period, connection=redis_connection, key=cache_key)
    count = redis_limiter.count(log_current_request=count_current_request)
    return {'count': count, 'limit': limit}


def is_ratelimited(request, group=None, fn=None, key=None, rate=None,
                   method=ALL, increment=False, reset=None, sliding_window=True,
                   max_offence_rate=None):
    if group is None:
        if hasattr(fn, '__self__'):
            parts = fn.__module__, fn.__self__.__class__.__name__, fn.__name__
        else:
            parts = (fn.__module__, fn.__name__)
        group = '.'.join(parts)

    if not getattr(settings, 'RATELIMIT_ENABLE', True):
        request.limited = False
        return False

    if not _method_match(request, method):
        return False

    old_limited = getattr(request, 'limited', False)

    if callable(rate):
        rate = rate(group, request)

    if rate is None:
        request.limited = old_limited
        return False

    if max_offence_rate is not None:
        offence_report = get_offence_count(request, group, max_offence_rate, key, method, sliding_window)
        offence_count = offence_report.get('count')
        if offence_count is not None:
            max_offence_count = offence_report.get('limit')
            if offence_count >= max_offence_count:
                get_offence_count(request, group, max_offence_rate, key, method,
                                  sliding_window, count_current_request=True)
                return True

    if sliding_window:
        usage = _get_usage_count(request, group, fn, key, rate, method, increment, reset, sliding_window)
    else:
        usage = get_usage_count(request, group, fn, key, rate, method, increment, reset)

    fail_open = getattr(settings, 'RATELIMIT_FAIL_OPEN', False)

    usage_count = usage.get('count')
    if usage_count is None:
        limited = not fail_open
    else:
        usage_limit = usage.get('limit')
        limited = usage_count > usage_limit

    if increment:
        request.limited = old_limited or limited

    if max_offence_rate is not None and limited:
        get_offence_count(request, group, max_offence_rate, key, method,
                          sliding_window, count_current_request=True)

    return limited


def get_usage_count(request, group=None, fn=None, key=None, rate=None,
                    method=ALL, increment=False, reset=None):
    if not key:
        raise ImproperlyConfigured('Ratelimit key must be specified')
    limit, period = _split_rate(rate)
    cache_name = getattr(settings, 'RATELIMIT_USE_CACHE', 'default')
    cache = caches[cache_name]

    if callable(key):
        value = key(group, request)
    elif key in _SIMPLE_KEYS:
        print(_SIMPLE_KEYS[key](request))
        value = _SIMPLE_KEYS[key](request)
    elif ':' in key:
        accessor, k = key.split(':', 1)
        if accessor not in _ACCESSOR_KEYS:
            raise ImproperlyConfigured('Unknown ratelimit key: %s' % key)
        value = _ACCESSOR_KEYS[accessor](request, k)
    elif '.' in key:
        mod, attr = key.rsplit('.', 1)
        keyfn = getattr(import_module(mod), attr)
        value = keyfn(group, request)
    else:
        raise ImproperlyConfigured(
            'Could not understand ratelimit key: %s' % key)

    cache_key = _make_cache_key(group, rate, value, method)

    if reset and callable(reset):
        should_reset = reset(request)
        if should_reset:
            cache.delete(cache_key)

    time_left = _get_window(value, period) - int(time.time())
    initial_value = 1 if increment else 0
    added = cache.add(cache_key, initial_value, period + EXPIRATION_FUDGE)
    if added:
        count = initial_value
    else:
        if increment:
            try:
                count = cache.incr(cache_key)
            except ValueError:
                count = initial_value
        else:
            count = cache.get(cache_key, initial_value)
    return {'count': count, 'limit': limit, 'time_left': time_left}


is_ratelimited.ALL = ALL
is_ratelimited.UNSAFE = UNSAFE


def is_authenticated(user):
    # is_authenticated was a method in Django < 1.10
    if callable(user.is_authenticated):
        return user.is_authenticated()
    else:
        return user.is_authenticated


def get_cache_key_for_ip_blocking(request, func):
    ip = _SIMPLE_KEYS['ip'](request)
    name = func.__name__
    keys = [ip, name]
    return 'ip_rl:' + hashlib.md5(u''.join(keys).encode('utf-8')).hexdigest()


def is_request_allowed(request, func, rate):
    limit, period = _split_rate(rate)
    cache_key = get_cache_key_for_ip_blocking(request, func)
    redis_set = IpRateLimiter(limit=limit, window=period, connection=redis_connection, key=cache_key)
    return redis_set.is_allowed()


def block_ip(request, func, function_to_get_attributes, rate):
    limit, period = _split_rate(rate)
    cache_key = get_cache_key_for_ip_blocking(request, func)
    redis_set = IpRateLimiter(limit=limit, window=period, connection=redis_connection, key=cache_key)
    hash_value = hashlib.md5(json.dumps(function_to_get_attributes(request))).hexdigest()
    redis_set.add(hash_value)


def unblock_ip(request, func, rate):
    limit, period = _split_rate(rate)
    cache_key = get_cache_key_for_ip_blocking(request, func)
    redis_set = IpRateLimiter(limit=limit, window=period, connection=redis_connection, key=cache_key)
    redis_set.delete()
