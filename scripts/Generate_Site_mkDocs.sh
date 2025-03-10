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

echo "Step 6/7: Generate URL shortcuts for all cheat sheets"

# Debug current location
echo "Current directory: $(pwd)"
echo "WORK directory: $WORK"

# Function to create redirect file
create_redirect() {
    local shortcut=$1
    local target=$2
    local redirect_file="$WORK/site/${shortcut}"
    
    echo "Creating redirect: /${shortcut} -> ${target}"
    
    # Create the redirect HTML file
    cat > "$redirect_file" << EOF
<!DOCTYPE html>
<html>
<head>
    <meta http-equiv="refresh" content="0; url=/${target}">
</head>
<body>
    Redirecting to <a href="/${target}">${target}</a>...
</body>
</html>
EOF
    
    # Also create .html version
    cp "$redirect_file" "${redirect_file}.html"
    
    # Verify creation and handle errors properly
    if [ -f "$redirect_file" ] && [ -f "${redirect_file}.html" ]; then
        echo "✅ Created shortcuts:"
        echo "  - /${shortcut}"
        echo "  - /${shortcut}.html"
    else
        echo "❌ Failed to create shortcuts for ${shortcut}"
        return 1
    fi
}

# Track used shortcuts to prevent duplicates
declare -A used_shortcuts

# Process all cheat sheet files
echo "Processing all cheat sheet files..."
find "$WORK/site/cheatsheets" -type f -name "*_Cheat_Sheet.html" | while read -r file; do
    filename=$(basename "$file")
    filepath=${file#"$WORK/site/"}
    
    #echo "Processing: $filename"
    
    # First try to find a match in redirects.yml
    shortcut=""
    if [ -f "redirects.yml" ]; then
        # Try to find a matching redirect in the YAML file
        while IFS=': ' read -r key target || [ -n "$key" ]; do
            # Skip comments and empty lines
            [[ $key =~ ^#.*$ ]] && continue
            [ -z "$key" ] && continue
            
            # Trim whitespace
            key=$(echo "$key" | xargs)
            target=$(echo "$target" | xargs)
            
            if [ "$target" = "$filepath" ]; then
                shortcut=$key
                break
            fi
        done < "redirects.yml"
    fi
    
    # If no shortcut found in redirects.yml, generate one
    if [ -z "$shortcut" ]; then
        # Generate shortcut from filename
        shortcut=$(echo "$filename" | awk -F'_' '{for(i=1;i<=NF;i++)printf "%s", substr($i,1,1)}' | tr '[:lower:]' '[:upper:]')
    fi
    
    # Handle duplicate shortcuts
    if [ "${used_shortcuts[$shortcut]}" ]; then
        echo "⚠️ Warning: Duplicate shortcut '$shortcut' for '$filename'. Original was for '${used_shortcuts[$shortcut]}'"
        # Append a number to make it unique
        count=2
        while [ "${used_shortcuts[${shortcut}${count}]}" ]; do
            ((count++))
        done
        shortcut="${shortcut}${count}"
    fi
    
    # Record this shortcut as used
    used_shortcuts[$shortcut]=$filepath
    
    # Create redirect
    create_redirect "$shortcut" "$filepath"
done

# Print all available shortcuts
echo "Available shortcuts:"
for shortcut in "${!used_shortcuts[@]}"; do
    echo "- /${shortcut} -> ${used_shortcuts[$shortcut]}"
done

echo "Step 7/7 Cleanup."
rm -rf cheatsheets
rm -rf custom_theme
rm mkdocs.yml

echo "Generation finished to the folder: $WORK/$GENERATED_SITE"

# Add redirect handling
echo "Generating redirect pages..."
mkdir -p $WORK/$GENERATED_SITE/redirects

# Process redirects.yml and generate redirect HTML files
#SITE_DIR="$WORK/$GENERATED_SITE"
python3 - <<EOF
import yaml
import os

REDIRECT_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <meta http-equiv="refresh" content="0;url={target_url}">
    <script>window.location.href = "{target_url}";</script>
</head>
<body>
    Redirecting to <a href="{target_url}">{target_url}</a>...
</body>
</html>
"""

def create_redirect_page(shortcut, target_url, output_dir):
    # Handle relative URLs
    if not target_url.startswith('http'):
        target_url = f'/{target_url}'
    
    content = REDIRECT_TEMPLATE.format(target_url=target_url)
    
    # Create redirect file
    with open(f'{output_dir}/{shortcut}.html', 'w') as f:
        f.write(content)

# Load redirects
with open('../scripts/redirects.yml', 'r') as f:
    try:
        redirects = yaml.safe_load(f)
    except yaml.YAMLError as e:
        print(f"Error parsing redirects.yml: {e}")
        exit(1)

# Create redirect pages
output_dir = '$WORK/$GENERATED_SITE'
for shortcut, target in redirects.items():
    create_redirect_page(shortcut, target, output_dir)
    print(f"Created redirect: {shortcut} -> {target}")

EOF

