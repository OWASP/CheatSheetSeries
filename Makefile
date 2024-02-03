.PHONY: help
.SILENT:

help:
	@grep -E '^[a-zA-Z_-]+:.*?# .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?# "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

install-python-requirements:  # Install Python 3 required libraries
	python -m pip install --user virtualenv; \
	virtualenv venv; \
	source venv/bin/activate; \
	python -m pip install -r requirements.txt

generate-site: install-python-requirements # Use custom-script to generate the website
	source venv/bin/activate; \
	(cd scripts && bash Generate_Site_mkDocs.sh)

serve: # Start's a Python http.server on port 8000 serving the content of ./generated/site
	# venv not required here as it's simply html
	python -m http.server -d generated/site

clean: # Clean up ephemeral build directories from the repo
	rm -rf generated venv
