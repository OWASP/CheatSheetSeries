![StatusTrackingBadge](https://img.shields.io/badge/Current_task-01-yellowgreen.svg)
![CSMigrationCounterBadge](https://img.shields.io/badge/CheatSheets_remaining_to_migrate-46-orange.svg)
![LicenseBadge](https://img.shields.io/badge/License-C_C-blue.svg)
[![LinterCheckStatusForReleasedCS](https://travis-ci.org/OWASP/CheatSheetSeries.svg?branch=master)](https://travis-ci.org/OWASP/CheatSheetSeries)

# Information & processus

This repository will contains all the cheat sheets of the project and will represent the V2 of the OWASP Cheat Sheet Series project.

A mass conversion from MEDIAWIKI to GITHUB MARKDOWN has been performed using this [tool](https://github.com/philipashlock/mediawiki-to-markdown) based on [PANDOC](https://pandoc.org/MANUAL.html) on 26th of december 2018 so content is frozen from this date.

# Folders

**cheatsheets_to_convert**: 
* Contains the cheat sheets markdown files converted with PANDOC and for which a convertion work is needed in order to be cleanly converted to Github markdown.

**cheatsheets_excluded**:
* Contains the cheat sheets markdown files converted with PANDOC and for which a discution must be made in order to decide if we include them into the V2 of the project due to the content has not been updated since a long time or is not relevant anymore.

**cheatsheets**: 
* Contains the final cheat sheets files. 
* Any `.md` file present at the root of this folder is considered as `converted` and the associated cheat sheet is considered released.

**assets**: 
* Contains the assets used by the cheat sheets (images...).
    * Naming convention is `[CHEAT_CHEET_MARKDOWN_FILE_NAME]_[IDENTIFIER].[EXTENSION]`
    * Use `PNG` format for the images.

**scripts**:
* Contains all the utility scripts used to operate the project (linter audit...).    

**templates**:
* Contains templates used for different kinds of files (cheatsheet...).

**.github**:
* Contains materials used to configure different behaviors of GitHub.

# Conversion rules

* Use the markdown syntax described in this [guide](https://guides.github.com/features/mastering-markdown/).
* Use this [sheet](https://gist.github.com/molomby/9bc092e4a125f529ae362de7e46e8176) for Superscript and Subscript characters.
* Store all assets in the **assets** folder and use the following syntax:
    * `![ALTERNATE_NAME](../assets/ASSET_NAME.png)` for the insertion of an image.
    * `[ALTERNATE_NAME](../assets/ASSET_NAME.EXT)` for the insertion of other kinds of media (pdf, zip...).
* Use ATX style (`#` syntax) for section head. 
* Use `**bold**` syntax for **bold** text.
* Use `*italic*` syntax for *italic* text.
* Use `TAB` for nested lists and not spaces.
* Use [code fencing syntax along syntax highlighting](https://help.github.com/articles/creating-and-highlighting-code-blocks/) for code snippet (prevent when possible horizontal scrollbar).
* No HTML code is allowed, only markdown syntax is allowed!
* Use this [site](https://www.tablesgenerator.com/markdown_tables) for generation of tables.
* Use a single new line between a section head and the begining of its content.

# Editor & validation policy

[Visual Studio Code](https://code.visualstudio.com/) is used for the work on the markdown files. 

The file **Project.code-workspace** is the workspace file in order to open the project in VSCode.

The following [plugin](https://github.com/DavidAnson/vscode-markdownlint) is used to validate the markdown content.

The file **.markdownlint.json** define the central validation policy applied at VSCode (IDE) and TravisCI (CI) levels.

Details about rules is [here](https://github.com/DavidAnson/markdownlint/blob/master/doc/Rules.md).

# Migration tasks list

**CS** = **C**heat **S**heet

* [ ] **Task 01:** Migrate all the CS files of the folder **cheatsheets_to_convert**.
* [ ] **Task 02:** Update each OWASP WIKI page associated to a CS in order to indicate the redirection to the GitHub location in order to do not break cross-reference to CS.
* [ ] **Task 03:** Create a Python script to auto-generate an markdown index page of all CS like this [page](https://www.owasp.org/index.php/Category:Cheatsheets).
* [x] **Task 04:** Create a markdown template file for the new CS.
* [ ] **Task 05:** Create the index page of the repository based on this README file to provide all the information about the repository and how to contribute.
* [ ] **Task 06:** Migrate the project [Trello board](https://trello.com/b/w020m3jQ) content to Issues in this repository
    * Create labels for: Request from OPC, Internal task...
* [ ] **Task 07:** Create all the materials to generate a PDF file of all the CS, automate it via a CircleCI job.
* [x] **Task 08:** Create a template for the pull request in order to add a checklist like the one created by the MSTG.
* [x] **Task 09:** Add a CI job to validate automatically the Pull Request when they are submitted.

# License

[![LICENSE](https://i.creativecommons.org/l/by-sa/3.0/88x31.png)](http://creativecommons.org/licenses/by-sa/3.0/)

# How to contribute?

Follow these steps:

1. Create an new [Issue](https://github.com/OWASP/CheatSheetSeries/issues/new/choose) using the `new_cheatsheet_proposal` template.
2. After a discution on the topic and if the cheat sheet proposal is accepted then:
    1. Clone this GitHub repository.
    2. Create the cheat sheet using the dedicated [template](templates/New_CheatSheet.md).
    3. Submit your [Pull Request](https://help.github.com/articles/creating-a-pull-request/).