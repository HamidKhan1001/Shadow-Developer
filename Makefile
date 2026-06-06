.PHONY: install run test test-cov lint parse-demo

# Install all dependencies
install:
	pip install -r src/requirements.txt

# Start the interceptor server locally
run:
	uvicorn src.interceptor.main:app --host 0.0.0.0 --port 8000 --reload

# Run tests
test:
	pytest tests/ -v

# Run tests with coverage
test-cov:
	pytest tests/ -v --cov=src --cov-report=term-missing

# Lint
lint:
	ruff check src/ tests/

# Parse the current codebase as demo context
parse-demo:
	python -m src.context.parser --path ./src --project-id shadow-developer-self

# Fire all demo prompts against the running server
demo:
	python scripts/run_demo.py
