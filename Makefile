
all: prettier lint bundle

prettier:
	npx prettier --check .

lint:
	npx eslint .
	npm run format:check
	npm run lint

bundle:
	npm run bundle

test:
	npm test
