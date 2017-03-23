=======
History
=======

1.0.1 (2017-03-23)
------------------

* Fixed an error on Python 2, FileNotFoundError was introduced in Python 3.

1.0.0 (2017-03-22)
------------------

* Added terminal size detection. Terminals with fewer than 80 columns should now display nicer reports.
* Added an option to load the database from the filesystem or a mirror that's reachable via http(s).
 This can be done by using the --db flag.
* Added an API Key option that uses pyup.io's vulnerability database.
* Added an option to cache the database locally for 2 hours. The default still is to not use the cache. Use the --cache flag.


0.6.0 (2017-03-10)
------------------

* Made the requirements parser more robust. The parser should no longer fail on editable requirements
  and requirements that are supplied by package URL.
* Running safety requires setuptools >= 16

0.5.1 (2016-11-08)
------------------

* Fixed a bug where not all requirement files were read correctly.

0.5.0 (2016-11-08)
------------------

* Added option to read requirements from files.

0.4.0 (2016-11-07)
------------------

* Filter out non-requirements when reading from stdin.

0.3.0 (2016-10-28)
------------------

* Added option to read from stdin.

0.2.2 (2016-10-21)
------------------

* Fix import errors on python 2.6 and 2.7.

0.2.1 (2016-10-21)
------------------

* Fix packaging bug.

0.2.0 (2016-10-20)
------------------

* Releasing first prototype.

0.1.0 (2016-10-19)
------------------

* First release on PyPI.
