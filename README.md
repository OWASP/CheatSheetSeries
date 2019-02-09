![StatusTrackingBadge](https://img.shields.io/badge/Current_task-01-yellowgreen.svg)
![CSMigrationCounterBadge](https://img.shields.io/badge/CheatSheets_remaining_to_migrate-12-orange.svg)
![LicenseBadge](https://img.shields.io/badge/License-C_C-blue.svg)
[![LinterCheckStatusForReleasedCS](https://travis-ci.org/OWASP/CheatSheetSeries.svg?branch=master)](https://travis-ci.org/OWASP/CheatSheetSeries)

# Welcome to OWASP Cheat Sheet Series V2

This repository contains all the cheat sheets of the project and represent the V2 of the [OWASP Cheat Sheet Series](https://www.owasp.org/index.php/OWASP_Cheat_Sheet_Series) project.

# Migration process

A mass conversion from Mediawiki to GitHub flavored Markdown format has been performed using this [tool](https://github.com/philipashlock/mediawiki-to-markdown) based on [PANDOC](https://pandoc.org/MANUAL.html) on **26th of december 2018** on all OWASP wiki pages flagged as [Cheatsheets](https://www.owasp.org/index.php/Category:Cheatsheets).

:warning: **Cheat Sheets content is now frozen from this date**:
* No modification will be performed anymore on the wiki content.
* Any modification will be made on this repository using the contribution issue templates defined in this repository.

# Cheat Sheets index

This [Index](Index.md) reference all migrated and released cheat sheets.

# Project leaders

* [Jim Manico](https://github.com/jmanico).
* [Dominique Righetto](https://github.com/righettod).

# Folders

**cheatsheets_to_convert**: 
* Contains the cheat sheets markdown files converted with PANDOC and for which a convertion work is needed in order to be cleanly converted to Github markdown.

**cheatsheets_excluded**:
* Contains the cheat sheets markdown files converted with PANDOC and for which a discution must be made in order to decide if we include them into the V2 of the project due to the content has not been updated since a long time or is not relevant anymore.

**cheatsheets**: 
* Contains the final cheat sheets files. 
* Any `.md` file present at the root of this folder is considered as `converted` and the associated cheat sheet is considered released.

**assets**: 
* Contains the assets used by the cheat sheets (images, pdf, zip...).
    * Naming convention is `[CHEAT_CHEET_MARKDOWN_FILE_NAME]_[IDENTIFIER].[EXTENSION]`
    * Use `PNG` format for the images.

**scripts**:
* Contains all the utility scripts used to operate the project (markdown linter audit, dead link identification...).    

**templates**:
* Contains templates used for different kinds of files (cheatsheet...).

**.github**:
* Contains materials used to configure different behaviors of GitHub.

# Offline website

Unfortunately, a PDF file generation is not possible because the content is cut in some cheat sheets like for example the abuse case one.

However, to propose the possibility the consult, in a full offline mode, the collection of all cheat sheets, a script to generate a offline site using [GitBook](https://toolchain.gitbook.com/) has been created. The script is [here](scripts/Generate_Site.sh).

* **book.json**: Gitbook configuration file.
* **Preface.md**: Project preface description applied on the generated site.

:construction: It's plan into the migration to provide a bundle with the site and generate it on a regular and automated basis.

Use the commands below to generate the site:

```bash
# Your python version must be >= 3.5.3
$ python --version
Python 3.5.3
# Dependencies:
#  sudo apt install -y nodejs
#  sudo npm install gitbook-cli -g
$ cd scripts
$ bash Generate_Site.sh
Generate a offline portable website with all the cheat sheets...
Step 1/5: Init work folder.
Step 2/5: Generate the summary markdown page.
Index updated.
Summary markdown page generated.
Step 3/5: Create the expected GitBook folder structure.
Step 4/5: Generate the site.
info: found 45 pages
info: found 86 asset files
info: >> generation finished with success in 14.2s !
Step 5/5: Cleanup.
Generation finished to the folder: ../generated/site
$ cd ../generated/site/
$ ls -l
drwxr-xr-x 1 Feb  3 11:05 assets
drwxr-xr-x 1 Feb  3 11:05 cheatsheets
drwxr-xr-x 1 Feb  3 11:05 gitbook
-rw-r--r-- 1 Feb  3 11:05 index.html
-rw-r--r-- 1 Feb  3 11:05 search_index.json
```

# Conversion rules

* Use the markdown syntax described in this [guide](https://guides.github.com/features/mastering-markdown/).
* Use this [sheet](https://gist.github.com/molomby/9bc092e4a125f529ae362de7e46e8176) for Superscript and Subscript characters.
* Use this [sheet](https://meta.askubuntu.com/a/7383) for Arrows (left, right, top, down) characters.
* Store all assets in the **assets** folder and use the following syntax:
    * `![ALTERNATE_NAME](../assets/ASSET_NAME.png)` for the insertion of an image.
    * `[ALTERNATE_NAME](../assets/ASSET_NAME.EXT)` for the insertion of other kinds of media (pdf, zip...).
* Use ATX style (`#` syntax) for section head. 
* Use `**bold**` syntax for **bold** text.
* Use `*italic*` syntax for *italic* text.
* Use `TAB` for nested lists and not spaces.
* Use [code fencing syntax along syntax highlighting](https://help.github.com/articles/creating-and-highlighting-code-blocks/) for code snippet (prevent when possible horizontal scrollbar).
* If you use `{{` or `}}` pattern in code fencing then add a space between the both curly braces (ex: `{ {`) otherwise it break GitBook generation process.
* Same remark about the cheat sheet file name, only the following syntax is allowed: `[a-zA-Z_]+`.
* No HTML code is allowed, only markdown syntax is allowed!
* Use this [site](https://www.tablesgenerator.com/markdown_tables) for generation of tables.
* Use a single new line between a section head and the begining of its content.

# Editor & validation policy

[Visual Studio Code](https://code.visualstudio.com/) is used for the work on the markdown files. It is also used for the work on the scripts.

The file **Project.code-workspace** is the workspace file in order to open the project in VSCode.

The following [plugin](https://github.com/DavidAnson/vscode-markdownlint) is used to validate the markdown content.

The file **.markdownlint.json** define the central validation policy applied at VSCode (IDE) and TravisCI (CI) levels.

Details about rules is [here](https://github.com/DavidAnson/markdownlint/blob/master/doc/Rules.md).

The file **.markdownlinkcheck.json** define the configuration used to validate using this [tool](https://github.com/tcort/markdown-link-check), at TravisCI level, all web and relatives links used in cheat sheets.

# Migration tasks list

:construction: All the tasks below represents the work that must be performed before that the V2 will be considered as Go Live! (**CS** = **C**heat **S**heet).

:triangular_flag_on_post: = Critical task.

* [ ] **Task 01:** :triangular_flag_on_post: Migrate all the CS files of the folder **cheatsheets_to_convert**.
* [ ] **Task 02:** :triangular_flag_on_post: Update each OWASP WIKI page associated to a CS in order to indicate the redirection to the GitHub location in order **to do not break cross-reference** to CS.
* [x] **Task 03:** Create [a Python script to auto-generate an markdown index page of all CS](scripts/Update_CheatSheets_Index.py) like this [page](https://www.owasp.org/index.php/Category:Cheatsheets).
* [x] **Task 04:** Create [a markdown template file for the new CS](templates/New_CheatSheet.md).
* [ ] **Task 05:** Create the index page of the repository based on this README file to provide all the information about the repository and how to contribute.
* [ ] **Task 06:** Migrate the project [Trello board](https://trello.com/b/w020m3jQ) content to Issues in this repository
    * Create labels for: Request from OPC, Internal task...
* [ ] **Task 07:** Create all the materials to generate a PDF file of all the CS, automate it via a CircleCI job.
* [x] **Task 08:** Create a template for the pull request in order to add a checklist like the one created by the MSTG.
* [x] **Task 09:** Add a CI job to [validate automatically the Pull Request](https://travis-ci.org/OWASP/CheatSheetSeries/pull_requests) when they are submitted.
* [ ] **Task 10:** :triangular_flag_on_post: Classify the CS collections in order to address the following important [problem](https://twitter.com/Kerberosmansour/status/1084063530251440128) raised by the community:

```text
Too many best practices:
It would be nice to have them structured so people drill down to Exactly what they want.
Like the @thoughtworks tech radar: https://www.thoughtworks.com/radar
```

**Idea:** In addition to the [alphabetical index](Index.md), the following indexes will be created: 
* An Index from that will classify every cheat sheets by [OWASP Proactive Controls sections](https://www.owasp.org/index.php/OWASP_Proactive_Controls).
* An Index from that will classify every cheat sheets by [OWASP Application Security Verification Standard Project sections](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project).

# License

[![LICENSE](https://i.creativecommons.org/l/by-sa/3.0/88x31.png)](http://creativecommons.org/licenses/by-sa/3.0/)

# How to setup my contributor environment?

Follow these steps:

1. Install [Visual Studio Code](https://code.visualstudio.com/) (named `VSCode` from here), it is cross platform and free.
2. Install this [plugin](https://github.com/DavidAnson/vscode-markdownlint#install) from VSCode.
3. Open the file [Project.code-workspace](Project.code-workspace) from VSCode via the menu `File > Open Workspace...`.
4. You are ready to contribute :+1:

:alarm_clock: Before to push my update to my fork, what I need to verify?

1. Ensure that the markdown file you have created/modified do not have any warnings/errors raised by the linter, you can see it in this bottom bar when the markdown file is opened in VSCode: 

![PluginWarningUI](assets/README_PluginWarningUI.png)

2. Ensure that the markdown file you have created/modified do not have any deadlinks. You can verify that by using this [plugin](https://www.npmjs.com/package/markdown-link-check), if you cannot use this plugin then, at least, verify that all the links are valid before to push:
    1. Install [NodeJS](https://nodejs.org/en/download/) to install NPM.
    2. Install the validation plugin via the command `npm install -g markdown-link-check`
    3. Use this commmand (from the repository root folder) on your markdown file to verify the presence of any deadlinks: 

```bash
$ markdown-link-check -c .markdownlinkcheck.json [MD_FILE]
```

See the example below:

```bash
$ markdown-link-check -c .markdownlinkcheck.json cheatsheets/Transaction_Authorization_Cheat_Sheet.md
FILE: cheatsheets/Transaction_Authorization_Cheat_Sheet.md
[✓] https://en.wikipedia.org/wiki/Time-based_One-time_Password_Algorithm
[✓] https://en.wikipedia.org/wiki/Chip_Authentication_Program
[✓] http://www.cl.cam.ac.uk/~sjm217/papers/fc09optimised.pdf
...
# If the program do not say to you that you have deadlinks so it's OK
# The identified deadlinks are showed using a red cross instead of a green tick before the link.
```

# How to contribute?

Follow these steps:

1. Create an new [Issue](https://github.com/OWASP/CheatSheetSeries/issues/new/choose) using either:
   - The `new_cheatsheet_proposal` template if you want to propose a new cheat sheet.
   - The `update_cheatsheet_proposal` template if you want to modify a existing cheat sheet.
2. After a discution on the topic/update and if the proposal is accepted by the project leaders then:
    1. Clone this GitHub repository.
    2. Either:
      - Create the cheat sheet using the dedicated [template](templates/New_CheatSheet.md) in case of a new cheat sheet.
      - Modify the target cheat sheet in case of a update/refactoring.
    3. Submit your [Pull Request](https://help.github.com/articles/creating-a-pull-request/).
    4. Verify that the CI job [applied on your Pull Request](https://travis-ci.org/OWASP/CheatSheetSeries/pull_requests) do not fail!
