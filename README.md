# Welcome to the OWASP Cheat Sheet Series

[![OWASP Flagship](https://img.shields.io/badge/owasp-flagship%20project-48A646.svg)](https://www.owasp.org/index.php/OWASP_Project_Inventory#tab=Flagship_Projects)
[![Creative Commons License](https://img.shields.io/github/license/OWASP/CheatSheetSeries)](https://creativecommons.org/licenses/by-sa/4.0/ "CC BY-SA 4.0")

Welcome to the official repository for the Open Web Application Security Project® (OWASP) Cheat Sheet Series project. The project focuses on providing good security practices for builders in order to secure their applications.

In order to read the cheat sheets and **reference** them, use the project [official website](https://cheatsheetseries.owasp.org). The project details can be viewed on the [OWASP main website](https://owasp.org/www-project-cheat-sheets/) without the cheat sheets.

:triangular_flag_on_post: Markdown files are the working sources and aren't intended to be referenced in any external documentation, books or websites.

## Cheat Sheet Series Team

### Project Leaders

- [Jim Manico](https://github.com/jmanico)
- [Jakub Maćkowski](https://github.com/mackowski)

### Core Team

- [Kevin W. Wall](https://github.com/kwwall)
- [Shlomo Zalman Heigh](https://github.com/szh)

## Chat With Us

We're easy to find on Slack:

1. Join the OWASP Group Slack with this [invitation link](https://owasp.org/slack/invite).
2. Join the [#cheatsheets channel](https://owasp.slack.com/messages/C073YNUQG).

Feel free to ask questions, suggest ideas, or share your best recipes.

## Contributions, Feature Requests, and Feedback

We are actively inviting new contributors! To start, please read the [contribution guide](CONTRIBUTING.md).

This project is only possible thanks to the work of many dedicated volunteers. Everyone is encouraged to help in ways large and small. Here are a few ways you can help:

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

Open Web Application Security Project and OWASP are registered trademarks of the OWASP Foundation, Inc.
