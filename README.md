# Information & processus

This repository will contains all the cheat sheets of the project and will represent the V2 of the OWASP Cheat Sheet Series project.

A mass conversion from MEDIAWIKI to GITHUB MARKDOWN has been performed using this [tool](https://github.com/philipashlock/mediawiki-to-markdown) based on [PANDOC](https://pandoc.org/MANUAL.html) on 26th of december 2018 so content is frozen from this date.

# Folders

**cheatsheets_to_convert**: 
* Contains the cheat sheets markdown files converted with PANDOC and that need to be modified in order to be cleanly converted to Github markdown.

**cheatsheets**: 
* Contains the final cheat sheets files. 
* Any `.md` file present at the root of this folder is considered as `converted` and the associated cheat sheet is considered released.

**assets**: 
* Contains the assets used by the cheat sheets (images...).
    * Naming convention is `[CHEAT_CHEET_MARKDOWN_FILE_NAME]_[IDENTIFIER].[EXTENSION]`
    * Use `PNG` format for the images.

# Conversion rules

* Use the markdown syntax described in this [guide](https://guides.github.com/features/mastering-markdown/).
* Use `**bold**` syntax for **bold** text.
* Use `*italic*` syntax for *italic* text.
* Use TAB for nested lists and not spaces.
* Use code fencing syntax along syntax highlighting for code snippet (prevent when possible horizontal scrollbar).
* No HTML code is allowed, only markdown syntax is allowed!
* Use this [site](https://www.tablesgenerator.com/markdown_tables) for generation of tables.
* Use a single new line between a title and the begining of its content.

# Editor & validation policy

[Visual Studio Code](https://code.visualstudio.com/) is used for the work on the markdown files. 

The file **vscode-project.code-workspace** is the workspace file in order to open the project in VSCode.

The following [plugin](https://github.com/DavidAnson/vscode-markdownlint) is used to validate the markdown content.

The file **.markdownlint.json** define the validation policy applied.

Details about rules is [here](https://github.com/DavidAnson/markdownlint/blob/master/doc/Rules.md).

# Migration tasks list

**CS** = **C**heat **S**heet

* [ ] **Task 01:** Migrate all the CS files of the folder **cheatsheets_to_convert**.
* [ ] **Task 02:** Update each OWASP WIKI page associated to a CS in order to indicate the redirection to the GitHub location in order to do not break cross-reference to CS.
* [ ] **Task 03:** Create a Python script to auto-generate an markdown index page of all CS like this [page](https://www.owasp.org/index.php/Category:Cheatsheets).
* [ ] **Task 04:** Create a markdown template file for the new CS.
* [ ] **Task 05:** Create the index page of the repository based on this README file to provide all the information about the repository and how to contribute.
* [ ] **Task 06:** Migrate the project [Trello board](https://trello.com/b/w020m3jQ) content to Issues in this repository
    * Create labels for: Request from OPC, Internal task...
* [ ] **Task 07:** Create all the materials to generate a PDF file of all the CS, automate it via a CircleCI job.
* [ ] **Task 08:** Create a template for the pull request in order to add a checklist like the one created by the MSTG.
* [ ] **Task 09:** Add a CI job to validate automatically the Pull Request when they are submitted.

# License

[![LICENSE](https://i.creativecommons.org/l/by-sa/3.0/88x31.png)](http://creativecommons.org/licenses/by-sa/3.0/)

# Status

**Task 1** is pending, 57 CS remaining to migrate :coffee: 

:satellite: Stay tuned...