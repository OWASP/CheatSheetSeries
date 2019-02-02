#!/bin/bash
# Dependencies:
#  sudo apt install -y nodejs
#  sudo npm install gitbook-cli -g
# Note:
#   PDF generation is not possible because the content is cutted in 
#   some CS like for example the abuse case one
WORK=_site
echo "Generate a offline portable website with all the cheat sheets..."
echo "Step 1/2: Generate the summary markdown page."
python Generate_CheatSheets_Summary.py
echo "Step 2/2: Generate the site."
cd ..
rm -rf $WORK 1>/dev/null 2>&1
cp Preface.md cheatsheets/.
gitbook install
gitbook build . $WORK --log=info
rm cheatsheets/Preface.md
rm cheatsheets/SUMMARY.md
rm -rf node_modules
echo "Generation finished to the folder: $WORK"