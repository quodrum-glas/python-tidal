.PHONY: lint test

lint:
	uv run ruff check tidalapi/ tests/
	uv run ruff format --check tidalapi/ tests/

test:
	uv run pytest --cov=tidalapi --cov-report=xml --cov-report=term-missing tests/
