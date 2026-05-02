.PHONY: lint test

lint:
	ruff check tidalapi/ tests/
	ruff format --check tidalapi/ tests/

test:
	pytest --cov=tidalapi --cov-report=xml --cov-report=term-missing tests/
