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

# Function to generate shortcut name from filename
generate_shortcut() {
    local filename=$1
    local shortcut=""
    
    # Remove file extension and common suffixes
    local basename=${filename%%.html}
    basename=${basename%%_Cheat_Sheet}
    
    # For cheat sheets, use first letters of each word
    shortcut=$(echo "$basename" | awk -F'_' '{for(i=1;i<=NF;i++)printf "%s", substr($i,1,1)}')
    
   # echo "$shortcut"
}

# Function to create redirect file
create_redirect() {
    local shortcut=$1
    local target=$2
    local redirect_file="$WORK/site/${shortcut}"
    
    #echo "Creating redirect: /${shortcut} -> ${target}"
    
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
    
    # Verify creation
    if [ -f "$redirect_file" ] && [ -f "${redirect_file}.html" ]; then
       # echo "✅ Created shortcuts:"
        echo "  - /${shortcut}"
        echo "  - /${shortcut}.html"
    else
        #echo "❌ Failed to create shortcuts for ${shortcut}"
    fi
}

# Process all cheat sheet files
echo "Processing all cheat sheet files..."
find "$WORK/site/cheatsheets" -type f -name "*_Cheat_Sheet.html" | while read -r file; do
    filename=$(basename "$file")
    filepath=${file#"$WORK/site/"}
    
    #echo "Processing: $filename"
    
    # Generate shortcut name
    shortcut=$(generate_shortcut "$filename")
    
    # Skip if no shortcut generated
    [ -z "$shortcut" ] && continue
    
    # Convert to uppercase
    #shortcut=$(echo "$shortcut" | tr '[:lower:]' '[:upper:]')
    
    # Create redirect
    create_redirect "$shortcut" "$filepath"
done

# Print all available shortcuts
#echo "Available shortcuts:"
for file in "$WORK"/site/[A-Z]*; do
    if [ -f "$file" ] && [[ ! "$file" =~ \.(html|xml|gz)$ ]]; then
        shortcut=$(basename "$file")
        target=$(grep -o 'url=/[^"]*' "$file" | cut -d'=' -f2)
        #echo "- /${shortcut} -> ${target}"
    fi
done

echo "Step 7/7 Cleanup."
rm -rf cheatsheets
rm -rf custom_theme
rm mkdocs.yml

echo "Generation finished to the folder: $WORK/$GENERATED_SITE"
