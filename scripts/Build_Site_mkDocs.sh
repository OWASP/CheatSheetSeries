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
mkdir $WORK/custom_theme

echo "Step 2/7: Generate the summary markdown page "
python Update_CheatSheets_Index.py
python Generate_RSS_Feed.py
python Excluded_CheatSheets_List.py

echo "Step 3/7: Create the expected MkDocs folder structure."

cp ../mkdocs.yml $WORK/.
cp ../Preface.md $WORK/cheatsheets/index.md
mv News.xml $WORK/cheatsheets/.
cp -r ../cheatsheets $WORK/cheatsheets/cheatsheets
cp -r ../assets $WORK/cheatsheets/assets
cp ../Index.md $WORK/cheatsheets/Glossary.md
cp ../IndexASVS.md $WORK/cheatsheets/IndexASVS.md
cp ../IndexProactiveControls.md $WORK/cheatsheets/IndexProactiveControls.md

cp ../Excluded.md $WORK/cheatsheets/Excluded.md

cp -r ../custom_theme/* $WORK/custom_theme/

if [[ "$OSTYPE" == "darwin"* ]]; then
        # Mac OSX
    sed -i '' "1i\\
        Title: Introduction\\
        " $WORK/cheatsheets/index.md
    sed -i '' 's/Index.md/Glossary.md/g' $WORK/cheatsheets/Glossary.md
    sed -i '' "1i\\
        Title: Index Alphabetical\\
        " $WORK/cheatsheets/Glossary.md
    sed -i '' "1i\\
        Title: Index ASVS\\
        " $WORK/cheatsheets/IndexASVS.md
    sed -i '' "1i\\
        Title: Index Proactive Controls\\
        " $WORK/cheatsheets/IndexProactiveControls.md

else
    sed -i "1iTitle: Introduction\n" $WORK/cheatsheets/index.md
    sed -i 's/Index.md/Glossary.md/g' $WORK/cheatsheets/Glossary.md
    sed -i "1iTitle: Index Alphabetical\n" $WORK/cheatsheets/Glossary.md
    sed -i "1iTitle: Index ASVS\n" $WORK/cheatsheets/IndexASVS.md
    sed -i "1iTitle: Index Proactive Controls\n" $WORK/cheatsheets/IndexProactiveControls.md
fi


echo "Step 4/7: Inserting markdown metadata."
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

