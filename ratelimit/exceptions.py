# from django.core.exceptions import PermissionDenied


class Ratelimited(Exception):
    def __init__(self, code):
        self.code = code

    def __str__(self):
        return repr(self.code)


try:
    raise Ratelimited(429)
except Ratelimited as e:
    print("Too many requests, Please retry after some time:", e.code) 