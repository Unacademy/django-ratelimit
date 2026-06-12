from setuptools import setup, find_packages

from ratelimit import __version__


setup(
    name='django-ratelimit',
    version=__version__,
    description='Cache-based rate-limiting for Django.',
    long_description=open('README.rst').read(),
    author='James Socol',
    author_email='me@jamessocol.com',
    url='https://github.com/jsocol/django-ratelimit',
    license='Apache Software License',
    packages=find_packages(exclude=['test_settings']),
    include_package_data=True,
    package_data={'': ['README.rst']},
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Web Environment',
        'Framework :: Django',
        'Framework :: Django',
        'Framework :: Django :: 3.2',
        'Framework :: Django :: 4.0',
        'Framework :: Django :: 4.1',
        'Framework :: Django :: 4.2',
        'Framework :: Django :: 5.0',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ]
)
