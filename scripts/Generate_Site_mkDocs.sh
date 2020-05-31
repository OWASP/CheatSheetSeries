GENERATED_SITE=site
WORK=../generated

bash Build_Site_mkDocs.sh

echo "Step 5/7: Generate the site."

cd $WORK
python -m mkdocs build

if [[ $? != 0 ]]
then
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
    # Mac OSX
    sed -i '' "1i\\
        ---\\
        redirect_from: \"/cheatsheets/Authorization_Testing_Automation.html\"\\
        ---\\
        " $WORK/$GENERATED_SITE/cheatsheets/Authorization_Testing_Automation_Cheat_Sheet.html
    sed -i '' "1i\\
        ---\\
        redirect_from: \"/cheatsheets/Injection_Prevention_Cheat_Sheet_in_Java.html\"\\
        ---\\
        " $WORK/$GENERATED_SITE/cheatsheets/Injection_Prevention_in_Java_Cheat_Sheet.html
    sed -i '' "1i\\
        ---\\
        redirect_from: \"/cheatsheets/JSON_Web_Token_Cheat_Sheet_for_Java.html\"\\
        ---\\
        " $WORK/$GENERATED_SITE/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html
    sed -i '' "1i\\
        ---\\
        redirect_from: \"/cheatsheets/Ruby_on_Rails_Cheatsheet.html\"\\
        ---\\
        " $WORK/$GENERATED_SITE/cheatsheets/Ruby_on_Rails_Cheat_Sheet.html
    sed -i '' "1i\\
        ---\\
        redirect_from: \"/cheatsheets/Nodejs_security_cheat_sheet.html\"\\
        ---\\
        " $WORK/$GENERATED_SITE/cheatsheets/Nodejs_Security_Cheat_Sheet.html
else
    sed -i "1i---\nredirect_from: \"/cheatsheets/Authorization_Testing_Automation.html\"\n---\n" $WORK/$GENERATED_SITE/cheatsheets/Authorization_Testing_Automation_Cheat_Sheet.html
    sed -i "1i---\nredirect_from: \"/cheatsheets/Injection_Prevention_Cheat_Sheet_in_Java.html\"\n---\n" $WORK/$GENERATED_SITE/cheatsheets/Injection_Prevention_in_Java_Cheat_Sheet.html
    sed -i "1i---\nredirect_from: \"/cheatsheets/JSON_Web_Token_Cheat_Sheet_for_Java.html\"\n---\n" $WORK/$GENERATED_SITE/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html
    sed -i "1i---\nredirect_from: \"/cheatsheets/Ruby_on_Rails_Cheatsheet.html\"\n---\n" $WORK/$GENERATED_SITE/cheatsheets/Ruby_on_Rails_Cheat_Sheet.html
    sed -i "1i---\nredirect_from: \"/cheatsheets/Nodejs_security_cheat_sheet.html\"\n---\n" $WORK/$GENERATED_SITE/cheatsheets/Nodejs_Security_Cheat_Sheet.html
fi

echo "Step 6-2/7: Handling redirect for excluded and redirect page"

python ../scripts/Excluded_CheatSheets_Redirect.py

echo "Step 7/7 Cleanup."
rm -rf cheatsheets
rm -rf custom_theme
rm mkdocs.yml

echo "Generation finished to the folder: $WORK/$GENERATED_SITE"
