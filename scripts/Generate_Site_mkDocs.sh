#!/bin/bash
# Dependencies:
#  pip install mkdocs
#  pip install mkdocs-material
#  pip install pymdown-extensions

set -e  # Exit on error

GENERATED_SITE=site
WORK=../generated
SITE_DIR="$WORK/site"
CHEATSHEETS_DIR="$WORK/cheatsheets"

check_dependencies() {
    local deps=("mkdocs" "mkdocs-material" "pymdown-extensions")
        python -c "import ${dep//-/_}" 2>/dev/null || {
            echo "Missing dependency: $dep"
            echo "Install with: pip install mkdocs mkdocs-material pymdown-extensions"
            exit 1
        }
    done
}

add_title() {
    local file=$1
    local title=$2
    
    if [[ "$OSTYPE" == "darwin"* ]]; then
        sed -i '' "1i\\
Title: $title\\
" "$file"
    else
        sed -i "1iTitle: $title\n" "$file"
    fi
}

# Create redirect HTML page
create_redirect() {
    local shortcut=$1
    local target=$2
    local output_file="$SITE_DIR/${shortcut}.html"
    
    cat > "$output_file" << EOF
<!DOCTYPE html>
<html>
<head>
    <meta http-equiv="refresh" content="0; url=/${target}">
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <script>window.location.href = "/${target}";</script>
</head>
<body>
    Redirecting to <a href="/${target}">${target}</a>...
</body>
</html>
EOF
}

echo "Generate a offline portable website with all the cheat sheets..."

echo "Step 1/7: Init work folder."
mkdir -p "$CHEATSHEETS_DIR"/{cheatsheets,assets}
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

add_title "$CHEATSHEETS_DIR/index.md" "Introduction"
add_title "$CHEATSHEETS_DIR/Glossary.md" "Index Alphabetical"
add_title "$CHEATSHEETS_DIR/IndexASVS.md" "Index ASVS"
add_title "$CHEATSHEETS_DIR/IndexMASVS.md" "Index MASVS"
add_title "$CHEATSHEETS_DIR/IndexProactiveControls.md" "Index Proactive Controls"
add_title "$CHEATSHEETS_DIR/IndexTopTen.md" "Index Top 10"

if [[ "$OSTYPE" == "darwin"* ]]; then
        " "$WORK/cheatsheets/index.md"
        " "$WORK/cheatsheets/IndexASVS.md"
    sed -i '' 's/Index.md/Glossary.md/g' "$CHEATSHEETS_DIR/Glossary.md"
else
    sed -i "1iTitle: Index Proactive Controls\n" $WORK/cheatsheets/IndexProactiveControls.md
    sed -i 's/Index.md/Glossary.md/g' "$CHEATSHEETS_DIR/Glossary.md"
fi

# Add titles to cheat sheets
for file in "$CHEATSHEETS_DIR/cheatsheets"/*.md; do
    filename=$(basename "$file" .md)
    filename="${filename%_Cheat_Sheet}"
    title="${filename//_/ }"
    add_title "$file" "$title"
done

echo "Step 4/5: Building site with MkDocs..."
echo "(This may take a few minutes for large sites...)"
cd "$WORK" || exit 1

python -m mkdocs build --verbose || {
    echo "ERROR: MkDocs build failed!"
    exit 1
}

if [ ! -d "$SITE_DIR" ]; then
    echo "ERROR: Site directory was not created!"
    exit 1
fi

echo "Site built successfully"

cat > "$SITE_DIR/.htaccess" << 'EOF'
RewriteEngine On
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME}.html -f
RewriteRule ^(.*)$ $1.html [L]
EOF

echo "Step 5/7: Generating URL shortcuts..."
if [ -f "../scripts/redirects.yml" ]; then
    python3 << PYTHON_SCRIPT
import yaml
import os
import shutil

site_dir = "$SITE_DIR"

def create_redirect(shortcut, target, site_dir):
    # Create a directory for the shortcut to allow /shortcut/ access
    target_path = os.path.join(site_dir, shortcut)
    
    # If a file exists with the shortcut name, remove it to avoid conflicts
    if os.path.isfile(target_path):
        os.remove(target_path)
        
    os.makedirs(target_path, exist_ok=True)
    
    # The 'index.html' inside the folder makes the clean URL work
    output_file = os.path.join(target_path, "index.html")
    target_url = target if target.startswith('http') else f'/{target}'

    html = f"""<!DOCTYPE html>
<html>
<head>
   <meta charset="UTF-8">
    <meta http-equiv="refresh" content="0; url={target_url}">
    <link rel="canonical" href="{target_url}">
    <script>window.location.href = "{target_url}";</script>
    <title>Redirecting...</title>
</head>
<body>
    Redirecting to <a href="{target_url}">{target_url}</a>...
</body>
</html>"""
    
    with open(output_file, 'w') as f:
        f.write(html)
    print(f"{shortcut} → {target}")

# Load redirects
try:
    with open('../scripts/redirects.yml', 'r') as f:
        redirects = yaml.safe_load(f)
        if redirects:
            for shortcut, target in redirects.items():
                # Clean the shortcut name (remove leading slashes or .html)
                clean_shortcut = shortcut.lstrip('/').replace('.html', '')
                create_redirect(clean_shortcut, target, site_dir)
            print(f"Created {len(redirects)} clean URL redirects")
        else:
            print("No redirects found in redirects.yml")
except Exception as e:
    print(f"Error processing redirects: {e}")
    import sys
    sys.exit(1)
PYTHON_SCRIPT
else
    echo "Warning: redirects.yml not found, skipping redirects"
fi
# echo "Step 6/7: Handling redirect for files that have changed"
# #Authorization_Testing_Automation.md -> Authorization_Testing_Automation_Cheat_Sheet.md
# #Drone_security_sheet.html -> Drone_Security_Cheat_Sheet.html
# #Injection_Prevention_Cheat_Sheet_in_Java.md -> Injection_Prevention_in_Java_Cheat_Sheet.md
# #JSON_WEB_Token_Cheat_Sheet_for_Java.md -> JSON_WEB_Token_for_Java_Cheat_Sheet.md
# #Ruby_on_Rails_Cheatsheet.md -> Ruby_on_Rails_Cheat_Sheet.md
# #Nodejs_security_cheat_sheet.html -> Nodejs_security_Cheat_Sheet.html

# if [[ "$OSTYPE" == "darwin"* ]]; then
#     # MacOS
#     sed -i '' "1i\\
#         ---\\
#         redirect_from: \"/cheatsheets/Authorization_Testing_Automation.html\"\\
#         ---\\
#         " "$WORK/$GENERATED_SITE/cheatsheets/Authorization_Testing_Automation_Cheat_Sheet.html"
#     sed -i '' "1i\\
#         ---\\
#         redirect_from: \"/cheatsheets/Drone_security_sheet.html\"\\
#         ---\\
#         " "$WORK/$GENERATED_SITE/cheatsheets/Drone_Security_Cheat_Sheet.html"
#     sed -i '' "1i\\
#         ---\\
#         redirect_from: \"/cheatsheets/Injection_Prevention_Cheat_Sheet_in_Java.html\"\\
#         ---\\
#         " "$WORK/$GENERATED_SITE/cheatsheets/Injection_Prevention_in_Java_Cheat_Sheet.html"
#     sed -i '' "1i\\
#         ---\\
#         redirect_from: \"/cheatsheets/JSON_Web_Token_Cheat_Sheet_for_Java.html\"\\
#         ---\\
#         " "$WORK/$GENERATED_SITE/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html"
#     sed -i '' "1i\\
#         ---\\
#         redirect_from: \"/cheatsheets/Ruby_on_Rails_Cheatsheet.html\"\\
#         ---\\
#         " "$WORK/$GENERATED_SITE/cheatsheets/Ruby_on_Rails_Cheat_Sheet.html"
#     sed -i '' "1i\\
#         ---\\
#         redirect_from: \"/cheatsheets/Nodejs_security_cheat_sheet.html\"\\
#         ---\\
#         " "$WORK/$GENERATED_SITE/cheatsheets/Nodejs_Security_Cheat_Sheet.html"
#     sed -i '' "1i\\
#         ---\\
#         redirect_from: \"/cheatsheets/Application_Logging_Vocabulary_Cheat_Sheet.html\"\\
#         ---\\
#         " "$WORK/$GENERATED_SITE/cheatsheets/Logging_Vocabulary_Cheat_Sheet.html"
# else
#     sed -i "1i---\nredirect_from: \"/cheatsheets/Authorization_Testing_Automation.html\"\n---\n" $WORK/$GENERATED_SITE/cheatsheets/Authorization_Testing_Automation_Cheat_Sheet.html
#     sed -i "1i---\nredirect_from: \"/cheatsheets/Drone_security_sheet.html\"\n---\n" $WORK/$GENERATED_SITE/cheatsheets/Drone_Security_Cheat_Sheet.html
#     sed -i "1i---\nredirect_from: \"/cheatsheets/Injection_Prevention_Cheat_Sheet_in_Java.html\"\n---\n" $WORK/$GENERATED_SITE/cheatsheets/Injection_Prevention_in_Java_Cheat_Sheet.html
#     sed -i "1i---\nredirect_from: \"/cheatsheets/JSON_Web_Token_Cheat_Sheet_for_Java.html\"\n---\n" $WORK/$GENERATED_SITE/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html
#     sed -i "1i---\nredirect_from: \"/cheatsheets/Ruby_on_Rails_Cheatsheet.html\"\n---\n" $WORK/$GENERATED_SITE/cheatsheets/Ruby_on_Rails_Cheat_Sheet.html
#     sed -i "1i---\nredirect_from: \"/cheatsheets/Nodejs_security_cheat_sheet.html\"\n---\n" $WORK/$GENERATED_SITE/cheatsheets/Nodejs_Security_Cheat_Sheet.html
#     sed -i "1i---\nredirect_from: \"/cheatsheets/Application_Logging_Vocabulary_Cheat_Sheet.html\"\n---\n" $WORK/$GENERATED_SITE/cheatsheets/Logging_Vocabulary_Cheat_Sheet.html
# fi

echo "Step 7/7 Cleanup."
rm -rf cheatsheets custom_theme mkdocs.yml

echo "Generation finished to the folder: $SITE_DIR"