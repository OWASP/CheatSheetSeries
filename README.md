# Welcome to the OWASP Cheat Sheet Series

[![OWASP Flagship](https://img.shields.io/badge/owasp-flagship%20project-48A646.svg)](https://www.owasp.org/index.php/OWASP_Project_Inventory#tab=Flagship_Projects)
![LicenseBadge](https://img.shields.io/badge/license-C_C-blue.svg)

Welcome to the official repository for the Open Web Application Security Project® (OWASP®) Cheat Sheet Series project. The project focuses on providing good security practices for builders in order to secure their applications.

In order to read the cheat sheets and **reference** them, use the project's [official website](https://cheatsheetseries.owasp.org). The project details can be viewed on the [OWASP® main website](https://owasp.org/www-project-cheat-sheets/) without the cheat sheets.

:triangular_flag_on_post: Markdown files are the working sources and are not intended to be referenced in any external documentation/book/website/etc.

## Cheat Sheet Series Team

### Project Leaders

- [Jim Manico](https://github.com/jmanico).
- [Elie Saad](https://github.com/ThunderSon).

### Core Team

- [Jakub Maćkowski](https://github.com/mackowski).
- [Robin Bailey](https://github.com/rbsec).

The core team contains a set of knowledgeable people that assist the project leaders in maintaining the repository and take actions on their own. The team follows a well documented process in issues and pull requests, whether in accepting or rejecting them.

## Chat With Us

We're easy to find on Slack:

1. Join the OWASP Group Slack with this [invitation link](https://owasp-slack.herokuapp.com/).
2. Join this project's [channel, #cheatsheets](https://owasp.slack.com/messages/C073YNUQG).

Feel free to ask questions, suggest ideas, or share your best recipes.

### Automated Build

This [link](https://cheatsheetseries.owasp.org/bundle.zip) allows you to download a build (ZIP archive) of the offline website.

## Editor & validation policy

[Visual Studio Code](https://code.visualstudio.com/) is used for the work on the markdown files. It is also used for the work on the scripts.

The file **Project.code-workspace** is the workspace file in order to open the project in VSCode.

The following [plugin](https://github.com/DavidAnson/vscode-markdownlint) is used to validate the markdown content.

The file **.markdownlint.json** defines the central validation policy applied at VSCode (IDE) and TravisCI (CI) levels.

Details about rules can be found [here](https://github.com/DavidAnson/markdownlint/blob/master/doc/Rules.md).

The file **.markdownlinkcheck.json** defines the configuration used to validate using this [tool](https://github.com/tcort/markdown-link-check), at TravisCI level, all web and relatives links used in cheat sheets.

## Contributors

- **From 2014 to 2018:** [V1](CONTRIBUTOR-V1.md) - Initial version of the project hosted on the [OWASP WIKI](https://wiki.owasp.org).
- **From 2019:** [V2](https://github.com/OWASP/CheatSheetSeries/graphs/contributors) - Hosted on [GitHub](https://github.com/OWASP/CheatSheetSeries).

## Special thanks

A special thank you to the following people for their help provided during the migration:

- [Dominique Righetto](https://github.com/righettod): For his special leadership and guidance.
- [Elie Saad](https://github.com/ThunderSon): For valuable help in updating the OWASP Wiki links for all the migrated cheat sheets.
- [Jakub Maćkowski](https://github.com/mackowski): For valuable help in updating the OWASP Wiki links for all the migrated cheat sheets.

## License

The entire project content is under the **[Creative Commons v3.0](https://creativecommons.org/licenses/by-sa/3.0/)** license.
