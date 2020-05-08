#!/bin/bash
# Dependencies:
#  pip install mkdocs
#  pip install mkdocs-material
#  pip install pymdown-extensions

GENERATED_SITE=site
WORK=../generated
echo "Generate a offline portable website with all the cheat sheets..."

echo "Step 1/7: Init work folder."
rm -rf $WORK 1>/dev/null 2>&1
mkdir $WORK
mkdir $WORK/cheatsheets

echo "Step 2/7: Generate the summary markdown page "
python Update_CheatSheets_Index.py
python Generate_CheatSheets_TOC.py
python Generate_RSS_Feed.py

echo "Step 3/7: Create the expected MkDocs folder structure."

cp ../mkdocs.yml $WORK/.
cp ../Preface.md $WORK/cheatsheets/.
mv TOC.md $WORK/cheatsheets/.
mv News.xml $WORK/cheatsheets/.
cp -r ../cheatsheets $WORK/cheatsheets/cheatsheets
cp -r ../assets $WORK/cheatsheets/assets
cp ../Index.md $WORK/cheatsheets/cheatsheets/Index.md
cp ../IndexASVS.md $WORK/cheatsheets/cheatsheets/IndexASVS.md
cp ../IndexProactiveControls.md $WORK/cheatsheets/cheatsheets/IndexProactiveControls.md


if [[ "$OSTYPE" == "darwin"* ]]; then
        # Mac OSX
    sed -i '' 's/assets\//..\/assets\//g' $WORK/cheatsheets/cheatsheets/Index.md
    sed -i '' 's/assets\//..\/assets\//g' $WORK/cheatsheets/cheatsheets/IndexASVS.md
    sed -i '' 's/assets\//..\/assets\//g' $WORK/cheatsheets/cheatsheets/IndexProactiveControls.md
    sed -i '' 's/cheatsheets\///g' $WORK/cheatsheets/cheatsheets/Index.md
    sed -i '' 's/cheatsheets\///g' $WORK/cheatsheets/cheatsheets/IndexASVS.md
    sed -i '' 's/cheatsheets\///g' $WORK/cheatsheets/cheatsheets/IndexProactiveControls.md
else
    sed -i 's/assets\//..\/assets\//g' $WORK/cheatsheets/cheatsheets/Index.md
    sed -i 's/assets\//..\/assets\//g' $WORK/cheatsheets/cheatsheets/IndexASVS.md
    sed -i 's/assets\//..\/assets\//g' $WORK/cheatsheets/cheatsheets/IndexProactiveControls.md
    sed -i 's/cheatsheets\///g' $WORK/cheatsheets/cheatsheets/Index.md
    sed -i 's/cheatsheets\///g' $WORK/cheatsheets/cheatsheets/IndexASVS.md
    sed -i 's/cheatsheets\///g' $WORK/cheatsheets/cheatsheets/IndexProactiveControls.md
fi


echo "Step 4/7: Inserting markdown metadata."
for fullfile in $WORK/cheatsheets/cheatsheets/*.md
do
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # Mac OSX
        filename=$(basename -- "$fullfile")
        filename="${filename%.*}"
        date=$(date '+%Y-%m-%d')
        echo "Processing file: $fullfile"
        sed -i '' "1i\\
            Title: ${filename//[_]/ }\\
            Date: $date\\
            " $fullfile
    else
        filename=$(basename -- "$fullfile")
        filename="${filename%.*}"
        date=$(date '+%Y-%m-%d')
        echo "Processing file: $fullfile"
        sed -i "1iTitle: ${filename//[_]/ }\nDate: $date\n" $fullfile
    fi
done

echo "Step 5/7: FavIcon"

mkdir $WORK/cheatsheets/img
cp ../assets/WebSite_Favicon.png $WORK/cheatsheets/img/apple-touch-icon-precomposed-152.png
cp ../assets/WebSite_Favicon.ico $WORK/cheatsheets/img/favicon.ico

echo "Step 6/7: Generate the site."

cd $WORK
python -m mkdocs build

if [[ $? != 0 ]]
then
    echo "Error detected during the generation of the site, generation failed!"
    exit 1
fi

echo "Step 7/7 Cleanup."
rm -rf cheatsheets
rm mkdocs.yml

echo "Generation finished to the folder: $WORK/$GENERATED_SITE"
