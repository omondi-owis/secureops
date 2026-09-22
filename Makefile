# MlinziOps make targets
.PHONY: help install migrate admin seed test run lint tree

help:
	@echo "make install   - create venv + install deps"
	@echo "make migrate   - apply Alembic migrations"
	@echo "make admin     - create admin account"
	@echo "make seed      - load labelled demo data"
	@echo "make test      - run pytest suite"
	@echo "make run       - run dev server on :8000"
	@echo "make lint      - compileall syntax check"

install:
	python3 -m venv .venv
	.venv/bin/pip install -r requirements.txt

migrate:
	.venv/bin/alembic upgrade head

admin:
	.venv/bin/python -m app.cli create-admin

seed:
	.venv/bin/python -m app.cli seed-demo

test:
	.venv/bin/python -m pytest -q

run:
	.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000

lint:
	.venv/bin/python -m compileall app scripts tests
