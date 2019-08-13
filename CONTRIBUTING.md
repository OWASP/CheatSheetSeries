# How to contribute?

**Notes:** 
* Regarding fixing of a typo in existing cheat sheet, you can directly create a Pull Request otherwise follow the process below.
* :warning: Pull Request marked as **WAITING_UPDATE** (indicate that the core team wait an update from the author of the Pull Request) that do not receive any update from the author in a timeframe superior to six months then will be closed.
* :warning: If the assignees of an issue do not provide any Pull Request in a timeframe superior to six months then the issue will go back to the **HELP_WANTED** state and assignees will be removed.

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
