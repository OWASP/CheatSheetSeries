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
mkdir $WORK/custom_theme/img

echo "Step 2/7: Generate the summary markdown page "
python Update_CheatSheets_Index.py
python Generate_RSS_Feed.py

echo "Step 3/7: Create the expected MkDocs folder structure."

cp ../mkdocs.yml $WORK/.
cp ../Preface.md $WORK/cheatsheets/index.md
mv News.xml $WORK/cheatsheets/.
cp -r ../cheatsheets $WORK/cheatsheets/cheatsheets
cp -r ../assets $WORK/cheatsheets/assets
cp ../Index.md $WORK/cheatsheets/Glossary.md
cp ../IndexASVS.md $WORK/cheatsheets/IndexASVS.md
cp ../IndexMASVS.md $WORK/cheatsheets/IndexMASVS.md
cp ../IndexProactiveControls.md $WORK/cheatsheets/IndexProactiveControls.md
cp ../IndexTopTen.md $WORK/cheatsheets/IndexTopTen.md

cp ../assets/WebSite_Favicon.ico $WORK/custom_theme/img/favicon.ico
cp ../assets/WebSite_Favicon.png $WORK/custom_theme/img/apple-touch-icon-precomposed-152.png

cp ./404.html $WORK/custom_theme/

if [[ "$OSTYPE" == "darwin"* ]]; then
    # MacOS
    sed -i '' "1i\\
        Title: Introduction\\
        " "$WORK/cheatsheets/index.md"
    sed -i '' 's/Index.md/Glossary.md/g' "$WORK/cheatsheets/Glossary.md"
    sed -i '' "1i\\
        Title: Index Alphabetical\\
        " "$WORK/cheatsheets/Glossary.md"
    sed -i '' "1i\\
        Title: Index ASVS\\
        " "$WORK/cheatsheets/IndexASVS.md"
    sed -i '' "1i\\
        Title: Index MASVS\\
        " "$WORK/cheatsheets/IndexMASVS.md"
    sed -i '' "1i\\
        Title: Index Proactive Controls\\
        " "$WORK/cheatsheets/IndexProactiveControls.md"
    sed -i '' "1i\\
        Title: Index Top 10\\
        " "$WORK/cheatsheets/IndexTopTen.md"
else
    sed -i "1iTitle: Introduction\n" $WORK/cheatsheets/index.md
    sed -i 's/Index.md/Glossary.md/g' $WORK/cheatsheets/Glossary.md
    sed -i "1iTitle: Index Alphabetical\n" $WORK/cheatsheets/Glossary.md
    sed -i "1iTitle: Index ASVS\n" $WORK/cheatsheets/IndexASVS.md
    sed -i "1iTitle: Index MASVS\n" $WORK/cheatsheets/IndexMASVS.md
    sed -i "1iTitle: Index Proactive Controls\n" $WORK/cheatsheets/IndexProactiveControls.md
    sed -i "1iTitle: Index Top 10\n" $WORK/cheatsheets/IndexTopTen.md
fi

echo "Step 4/7: Inserting markdown metadata."
for fullfile in "$WORK"/cheatsheets/cheatsheets/*.md
do
    filename=$(basename -- "$fullfile")
    filename="${filename%_Cheat_Sheet.*}"

    echo "Processing file: $fullfile - $filename"
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # MacOS
        sed -i '' "1i\\
            Title: ${filename//[_]/ }\\
            " "$fullfile"
    else
        sed -i "1iTitle: ${filename//[_]/ }\n" "$fullfile"
    fi
done

echo "Step 5/7: Generate the site."

cd $WORK || exit

if ! python -m mkdocs build; then
    echo "Error detected during the generation of the site, generation failed!"
    exit 1
fi

echo "Step 6/7: Handling redirect for files that have changed"
#Authorization_Testing_Automation.md -> Authorization_Testing_Automation_Cheat_Sheet.md
#Injection_Prevention_Cheat_Sheet_in_Java.md -> Injection_Prevention_in_Java_Cheat_Sheet.md
#JSON_WEB_Token_Cheat_Sheet_for_Java.md -> JSON_WEB_Token_for_Java_Cheat_Sheet.md
#Ruby_on_Rails_Cheatsheet.md -> Ruby_on_Rails_Cheat_Sheet.md
#Nodejs_security_cheat_sheet.html -> Nodejs_security_Cheat_Sheet.html

if [[ "$OSTYPE" == "darwin"* ]]; then
    # MacOS
    sed -i '' "1i\\
        ---\\
        redirect_from: \"/cheatsheets/Authorization_Testing_Automation.html\"\\
        ---\\
        " "$WORK/$GENERATED_SITE/cheatsheets/Authorization_Testing_Automation_Cheat_Sheet.html"
    sed -i '' "1i\\
        ---\\
        redirect_from: \"/cheatsheets/Injection_Prevention_Cheat_Sheet_in_Java.html\"\\
        ---\\
        " "$WORK/$GENERATED_SITE/cheatsheets/Injection_Prevention_in_Java_Cheat_Sheet.html"
    sed -i '' "1i\\
        ---\\
        redirect_from: \"/cheatsheets/JSON_Web_Token_Cheat_Sheet_for_Java.html\"\\
        ---\\
        " "$WORK/$GENERATED_SITE/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html"
    sed -i '' "1i\\
        ---\\
        redirect_from: \"/cheatsheets/Ruby_on_Rails_Cheatsheet.html\"\\
        ---\\
        " "$WORK/$GENERATED_SITE/cheatsheets/Ruby_on_Rails_Cheat_Sheet.html"
    sed -i '' "1i\\
        ---\\
        redirect_from: \"/cheatsheets/Nodejs_security_cheat_sheet.html\"\\
        ---\\
        " "$WORK/$GENERATED_SITE/cheatsheets/Nodejs_Security_Cheat_Sheet.html"
    sed -i '' "1i\\
        ---\\
        redirect_from: \"/cheatsheets/Application_Logging_Vocabulary_Cheat_Sheet.html\"\\
        ---\\
        " "$WORK/$GENERATED_SITE/cheatsheets/Logging_Vocabulary_Cheat_Sheet.html"
else
    sed -i "1i---\nredirect_from: \"/cheatsheets/Authorization_Testing_Automation.html\"\n---\n" $WORK/$GENERATED_SITE/cheatsheets/Authorization_Testing_Automation_Cheat_Sheet.html
    sed -i "1i---\nredirect_from: \"/cheatsheets/Injection_Prevention_Cheat_Sheet_in_Java.html\"\n---\n" $WORK/$GENERATED_SITE/cheatsheets/Injection_Prevention_in_Java_Cheat_Sheet.html
    sed -i "1i---\nredirect_from: \"/cheatsheets/JSON_Web_Token_Cheat_Sheet_for_Java.html\"\n---\n" $WORK/$GENERATED_SITE/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html
    sed -i "1i---\nredirect_from: \"/cheatsheets/Ruby_on_Rails_Cheatsheet.html\"\n---\n" $WORK/$GENERATED_SITE/cheatsheets/Ruby_on_Rails_Cheat_Sheet.html
    sed -i "1i---\nredirect_from: \"/cheatsheets/Nodejs_security_cheat_sheet.html\"\n---\n" $WORK/$GENERATED_SITE/cheatsheets/Nodejs_Security_Cheat_Sheet.html
    sed -i "1i---\nredirect_from: \"/cheatsheets/Application_Logging_Vocabulary_Cheat_Sheet.html\"\n---\n" $WORK/$GENERATED_SITE/cheatsheets/Logging_Vocabulary_Cheat_Sheet.html
fi

echo "Step 7/7 Cleanup."
rm -rf cheatsheets
rm -rf custom_theme
rm mkdocs.yml

echo "Generation finished to the folder: $WORK/$GENERATED_SITE"
