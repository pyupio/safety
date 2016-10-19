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

docs: ## generate Sphinx HTML documentation, including API docs
	rm -f docs/safety.rst
	rm -f docs/modules.rst
	sphinx-apidoc -o docs/ safety
	$(MAKE) -C docs clean
	$(MAKE) -C docs html
	$(BROWSER) docs/_build/html/index.html

servedocs: docs ## compile the docs watching for changes
	watchmedo shell-command -p '*.rst' -c '$(MAKE) -C docs html' -R -D .

release: clean ## package and upload a release
	python setup.py sdist upload
	python setup.py bdist_wheel upload
