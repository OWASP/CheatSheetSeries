# Welcome to the OWASP Cheat Sheet Series

[![OWASP Flagship](https://img.shields.io/badge/owasp-flagship%20project-48A646.svg)](https://www.owasp.org/index.php/OWASP_Project_Inventory#tab=Flagship_Projects)
![LicenseBadge](https://img.shields.io/badge/license-C_C-blue.svg)

This repository contains all the cheat sheets of the project and represent the V2 of the **OWASP Cheat Sheet Series** project.

Links:
* [OWASP home page of the project](https://owasp.org/www-project-cheat-sheets/)
* [Official website](https://cheatsheetseries.owasp.org)

## Reference to the Cheat Sheets

When a reference to a cheat sheet needs to be created, then a link pointing to the project (generated) official web site hosted on **https://cheatsheetseries.owasp.org** must be used.

:triangular_flag_on_post: Markdown files are the working sources and are not intended to be referenced in any external documentation/book/website/etc.

## Cheat Sheet Series Team

### Project Leaders

* [Jim Manico](https://github.com/jmanico).
* [Elie Saad](https://github.com/ThunderSon).

### Core Team

* [Jakub Maćkowski](https://github.com/mackowski).
* [Robin Bailey](https://github.com/rbsec).

The core team contains a set of knowledgeable people that assist the project leaders in maintaining the repository and take on actions on their own. The team follows a well documented process in issues and pull requests, whether in accepting or rejecting them.

## Chat With Us

We're easy to find on Slack:

1. Join the OWASP Group Slack with this [invitation link](https://owasp-slack.herokuapp.com/).
2. Join this project's [channel, #cheatsheets](https://owasp.slack.com/messages/C073YNUQG).

Feel free to ask questions, suggest ideas, or share your best recipes.

### Automated Build

This [link](https://cheatsheetseries.owasp.org/bundle.zip) allows you to download a build (ZIP archive) of the offline website.

## Conversion Rules

* Use the markdown syntax described in this [guide](https://guides.github.com/features/mastering-markdown/).
* Use this [sheet](https://gist.github.com/molomby/9bc092e4a125f529ae362de7e46e8176) for superscript and subscript characters.
* Use this [sheet](https://meta.askubuntu.com/a/7383) for arrows (left, right, top, down) characters.
* Store all assets in the **assets** folder and use the following syntax:
    * `![ALTERNATE_NAME](../assets/ASSET_NAME.png)` for the insertion of an image. Use `PNG` format for the images (this [software](https://www.gimp.org/downloads/) can be used to handle format conversion).
    * `[ALTERNATE_NAME](../assets/ASSET_NAME.EXT)` for the insertion of other kinds of media (PDF, ZIP etc.).
* Use ATX style (`#` syntax) for section head. 
* Use `**bold**` syntax for **bold** text.
* Use `*italic*` syntax for *italic* text.
* Use `TAB` for nested lists and not spaces.
* Use [code fencing syntax along syntax highlighting](https://help.github.com/articles/creating-and-highlighting-code-blocks/) for code snippet (prevent when possible horizontal scrollbar).
* If you use `{{` or `}}` pattern in code fencing then add a space between both curly braces (ex: `{ {`) otherwise it will break the GitBook generation process.
* Same remark about the cheat sheet file name, only the following syntax is allowed: `[a-zA-Z_]+`.
* No HTML code is allowed, only markdown syntax is allowed.
* Use this [site](https://www.tablesgenerator.com/markdown_tables) for generation of tables.
* Use a single new line between a section head and the beginning of its content.

## Editor & validation policy

[Visual Studio Code](https://code.visualstudio.com/) is used for the work on the markdown files. It is also used for the work on the scripts.

The file **Project.code-workspace** is the workspace file in order to open the project in VSCode.

The following [plugin](https://github.com/DavidAnson/vscode-markdownlint) is used to validate the markdown content.

The file **.markdownlint.json** defines the central validation policy applied at VSCode (IDE) and TravisCI (CI) levels.

Details about rules can be found [here](https://github.com/DavidAnson/markdownlint/blob/master/doc/Rules.md).

The file **.markdownlinkcheck.json** defines the configuration used to validate using this [tool](https://github.com/tcort/markdown-link-check), at TravisCI level, all web and relatives links used in cheat sheets.

## Contributors

* **From 2014 to 2018:** [V1](CONTRIBUTOR-V1.md) - Initial version of the project hosted on the [OWASP WIKI](https://wiki.owasp.org).
* **From 2019:** [V2](https://github.com/OWASP/CheatSheetSeries/graphs/contributors) - Hosted on [GitHub](https://github.com/OWASP/CheatSheetSeries).

## Special thanks

A special thank you to the following people for their help provided during the migration:

* [Dominique Righetto](https://github.com/righettod): For his special leadership and guidance.
* [Elie Saad](https://github.com/ThunderSon): For valuable help in updating the OWASP Wiki links for all the migrated cheat sheets.
* [Jakub Maćkowski](https://github.com/mackowski): For valuable help in updating the OWASP Wiki links for all the migrated cheat sheets.

## License

The entire project content is under the **[Creative Commons v3.0](https://creativecommons.org/licenses/by-sa/3.0/)** license.
