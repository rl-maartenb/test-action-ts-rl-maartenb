
all: prettier lint bundle

prettier:
	npx prettier --check .

lint:
	npx eslint .

bundle:
	npm run bundle

test:
	npm test
