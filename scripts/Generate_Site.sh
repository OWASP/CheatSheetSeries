#!/bin/bash
# Dependencies:
#  sudo apt install -y nodejs
#  sudo npm install gitbook-cli -g
# Note:
#   PDF generation is not possible because the content is cut in
#   some CS like for example the abuse case one
GENERATED_SITE=site
WORK=../generated
echo "Generate a offline portable website with all the cheat sheets..."
echo "Step 1/5: Init work folder."
rm -rf $WORK 1>/dev/null 2>&1
mkdir $WORK
mkdir $WORK/cheatsheets
echo "Step 2/5: Generate the summary markdown page and the RSS News feed."
python Update_CheatSheets_Index.py
python Generate_CheatSheets_TOC.py
python Generate_RSS_Feed.py
echo "Step 3/5: Create the expected GitBook folder structure."
cp ../book.json $WORK/.
cp ../Preface.md $WORK/cheatsheets/.
mv TOC.md $WORK/cheatsheets/.
mv News.xml $WORK/.
cp -r ../cheatsheets $WORK/cheatsheets/cheatsheets
cp -r ../assets $WORK/cheatsheets/assets
cp ../Index.md $WORK/cheatsheets/cheatsheets/Index.md
cp ../IndexASVS.md $WORK/cheatsheets/cheatsheets/IndexASVS.md
cp ../IndexMASVS.md $WORK/cheatsheets/cheatsheets/IndexMASVS.md
cp ../IndexProactiveControls.md $WORK/cheatsheets/cheatsheets/IndexProactiveControls.md
cp ../IndexTopTen.md $WORK/cheatsheets/cheatsheets/IndexTopTen.md
sed -i 's/assets\//..\/assets\//g' $WORK/cheatsheets/cheatsheets/Index.md
sed -i 's/assets\//..\/assets\//g' $WORK/cheatsheets/cheatsheets/IndexASVS.md
sed -i 's/assets\//..\/assets\//g' $WORK/cheatsheets/cheatsheets/IndexMASVS.md
sed -i 's/assets\//..\/assets\//g' $WORK/cheatsheets/cheatsheets/IndexTopTen.md
sed -i 's/cheatsheets\///g' $WORK/cheatsheets/cheatsheets/Index.md
sed -i 's/cheatsheets\///g' $WORK/cheatsheets/cheatsheets/IndexASVS.md
sed -i 's/cheatsheets\///g' $WORK/cheatsheets/cheatsheets/IndexMASVS.md
sed -i 's/cheatsheets\///g' $WORK/cheatsheets/cheatsheets/IndexProactiveControls.md
sed -i 's/cheatsheets\///g' $WORK/cheatsheets/cheatsheets/IndexTopTen.md
echo "Step 4/5: Generate the site."
cd $WORK
gitbook install --log=error
gitbook build . $WORK/$GENERATED_SITE --log=info
if [[ $? != 0 ]]
then
    echo "Error detected during the generation of the site, generation failed!"
    exit 1
fi
# Move the generated RSS feed
mv News.xml site/.
# Replace the default favicon by the OWASP one
# I did not achieve to find a stable and "trustable" gitbook plugin to do that
# So I only replace the default images: https://www.npmjs.com/search?q=gitbook%20favicon
cp ../assets/WebSite_Favicon.png site/gitbook/images/apple-touch-icon-precomposed-152.png
cp ../assets/WebSite_Favicon.ico site/gitbook/images/favicon.ico
echo "Step 5/5: Cleanup."
rm -rf cheatsheets
rm -rf node_modules
rm book.json
echo "Generation finished to the folder: $WORK/$GENERATED_SITE"
