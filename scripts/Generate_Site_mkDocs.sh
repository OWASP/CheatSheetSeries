#!/bin/bash
# Dependencies:
#  pip install mkdocs
#  pip install mkdocs-material
#  pip install pymdown-extensions

GENERATED_SITE=site
WORK=../generated
date=$(date '+%Y-%m-%d')

echo "Generate a offline portable website with all the cheat sheets..."

echo "Step 1/6: Init work folder."
rm -rf $WORK 1>/dev/null 2>&1
mkdir $WORK
mkdir $WORK/cheatsheets
mkdir $WORK/custom_theme
mkdir $WORK/custom_theme/img

echo "Step 2/6: Generate the summary markdown page "
python Update_CheatSheets_Index.py
python Generate_RSS_Feed.py

echo "Step 3/6: Create the expected MkDocs folder structure."

cp ../mkdocs.yml $WORK/.
cp ../Preface.md $WORK/cheatsheets/index.md
mv News.xml $WORK/cheatsheets/.
cp -r ../cheatsheets $WORK/cheatsheets/cheatsheets
cp -r ../assets $WORK/cheatsheets/assets
cp ../Index.md $WORK/cheatsheets/glossary.md
cp ../IndexASVS.md $WORK/cheatsheets/IndexASVS.md
cp ../IndexProactiveControls.md $WORK/cheatsheets/IndexProactiveControls.md

cp ../assets/WebSite_Favicon.ico $WORK/custom_theme/img/favicon.ico
cp ../assets/WebSite_Favicon.png $WORK/custom_theme/img/apple-touch-icon-precomposed-152.png

cp ./404.html $WORK/custom_theme/

if [[ "$OSTYPE" == "darwin"* ]]; then
        # Mac OSX
    sed -i '' 's/Index.md/glossary.md/g' $WORK/cheatsheets/glossary.md
    sed -i '' "1i\\
        Title: Index Alphabetical\\
        " $WORK/cheatsheets/glossary.md
    sed -i '' "1i\\
        Title: Index ASVS\\
        " $WORK/cheatsheets/IndexASVS.md
    sed -i '' "1i\\
        Title: Index Proactive Controls\\
        " $WORK/cheatsheets/IndexProactiveControls.md

else
    sed -i 's/Index.md/glossary.md/g' $WORK/cheatsheets/glossary.md
    sed -i "1iTitle: Index Alphabetical\n" $WORK/cheatsheets/glossary.md
    sed -i "1iTitle: Index ASVS\n" $WORK/cheatsheets/IndexASVS.md
    sed -i "1iTitle: Index Proactive Controls\n" $WORK/cheatsheets/IndexProactiveControls.md
fi


echo "Step 4/6: Inserting markdown metadata."
for fullfile in $WORK/cheatsheets/cheatsheets/*.md
do
    filename=$(basename -- "$fullfile")
    filename="${filename%_Cheat_Sheet.*}"

    echo "Processing file: $fullfile - $filename"
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # Mac OSX
        sed -i '' "1i\\
            Title: ${filename//[_]/ }\\
            " $fullfile
    else
        sed -i "1iTitle: ${filename//[_]/ }\n" $fullfile
    fi
done

echo "Step 5/6: Generate the site."

cd $WORK
python -m mkdocs build

if [[ $? != 0 ]]
then
    echo "Error detected during the generation of the site, generation failed!"
    exit 1
fi

echo "Step 6/6 Cleanup."
rm -rf cheatsheets
rm -rf custom_theme
rm mkdocs.yml

echo "Generation finished to the folder: $WORK/$GENERATED_SITE"
