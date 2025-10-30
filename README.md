# OWASP Cheat Sheet Series

The OWASP Cheat Sheet Series project provides high-value information on specific application security topics.

## Authors

- Jim Manico  
- Tanya Janca  
- Andrew van der Stock  

## Chat With Us

Join us on our [Slack](https://owasp.org/slack)

## Conversion Rules

- Use Markdown (.md) files for cheatsheets.  
- Follow consistent heading levels.  
- Keep lines under 120 characters.  

## Editor

<<<<<<< HEAD
We use Visual Studio Code with markdownlint plugin for linting.
=======
We are actively inviting new contributors! To start, please read the [contribution guide](CONTRIBUTING.md) and our [How To Make A Cheatsheet guide](GUIDELINE.md).
>>>>>>> 72799ffcc4fc4f015fd12d45dfea3399c6756edf

## Status

<<<<<<< HEAD
All cheatsheets are continuously improved and reviewed.
=======
- Read the current content and help us fix any spelling mistakes or grammatical errors.
- Choose an existing [issue](https://github.com/OWASP/CheatSheetSeries/issues) on GitHub and submit a pull request to fix it.
- Open a new issue to report an opportunity for improvement.

### Automated Build

This [link](https://cheatsheetseries.owasp.org/bundle.zip) allows you to download a build (ZIP archive) of the offline website.

### Local Build [![pyVersion3x](https://img.shields.io/badge/python-3.x-blue.svg)](https://www.python.org/downloads/)

The OWASP Cheat Sheet Series website can be built and tested locally by issuing the following commands:

```sh
make install-python-requirements
make generate-site
make serve  # Binds port 8000
```

### Linting

To check markdown and terminology:

```sh
npm run lint-markdown
npm run lint-terminology
```

To auto-fix linting issues:

```sh
npm run lint-markdown-fix
npm run lint-terminology-fix
```

### Container Build

The OWASP Cheat Sheet Series website can be built and tested locally inside a container by issuing the following commands:

#### Docker

```sh
docker build -t cheatsheetseries .
docker run --name cheatsheetseries -p 8000:8000 cheatsheetseries
```

#### Podman

```sh
podman build -t cheatsheetseries .
podman run --name cheatsheetseries -p 8000:8000 localhost/cheatsheetseries
```

## Contributors

- **From 2014 to 2018:** [V1](CONTRIBUTOR-V1.md) - Initial version of the project hosted on the [OWASP WIKI](https://wiki.owasp.org).
- **From 2019:** [V2](https://github.com/OWASP/CheatSheetSeries/graphs/contributors) - Hosted on [GitHub](https://github.com/OWASP/CheatSheetSeries).

## Special thanks

A special thank you to the following people for their help provided during the migration:

- [Dominique Righetto](https://github.com/righettod): For his special leadership and guidance.
- [Elie Saad](https://github.com/ThunderSon): For valuable help in updating the OWASP Wiki links for all the migrated cheat sheets and for years of leadership and other project support.
- [Jakub Maćkowski](https://github.com/mackowski): For valuable help in updating the OWASP Wiki links for all the migrated cheat sheets.

Open Worldwide Application Security Project and OWASP are registered trademarks of the OWASP Foundation, Inc.
>>>>>>> 72799ffcc4fc4f015fd12d45dfea3399c6756edf
