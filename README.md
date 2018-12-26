# Information & processus

This repository will contains all the cheat sheets of the project and will represent the V2 of the OWASP Cheat Sheet Series project.

A first mass conversion from MEDIAWIKI to GITHUB MARKDOWN has been performed using this [tool](https://github.com/philipashlock/mediawiki-to-markdown) based on [PANDOC](https://pandoc.org/MANUAL.html) on 26th of december 2018.

# Folders

**cheatsheets_to_convert**: 
* Contains the cheat sheets markdown files converted with PANDOC and that need to be modified in order to be cleanly converted to Github markdown.

**cheatsheets**: 
* Contains the final cheat sheets files. 
* Any `.md` file present at the root of this folder is considered as `converted` and the associated cheat sheet is considered released.

**assets**: 
* Contains the assets used by the cheat sheets (images...).
    *  Naming convention is `[CHEAT_CHEET_MARKDOWN_FILE_NAME]_[IDENTIFIER].[EXTENSION]`
    * Use `PNG` format for the images.


# Conversion rules

* Use the markdown syntax described in this [guide](https://guides.github.com/features/mastering-markdown/).
* Use `**bold**` syntax for **bold** text.
* Use `*italic*` syntax for *italic* text.
* Use TAB for nested lists and not spaces.
* Use code fencing syntax along syntax highlighting for code snippet (prevent horizontal scrollbar).
* No HTML code is allowed, only markdown tag are allowed!
* Use this [site](https://www.tablesgenerator.com/markdown_tables) for generation of tables.
* Use a single new line between a title and the begining of its content.

# Status

The migration is pending...

Stay tuned :smiley: