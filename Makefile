lint: ## check style with flake8
	flake8 safety tests

test: ## run tests quickly with the default Python

		python setup.py test

test-all: ## run tests on every Python version with tox
	tox

coverage: ## check code coverage quickly with the default Python

		coverage run --source safety setup.py test

		coverage report -m
		coverage html
		$(BROWSER) htmlcov/index.html

release: clean ## package and upload a release
	python setup.py sdist upload
	python setup.py bdist_wheel upload
