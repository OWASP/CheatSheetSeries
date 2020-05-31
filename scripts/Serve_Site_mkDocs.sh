WORK=../generated

bash Build_Site_mkDocs.sh

echo "Step 5/7: Serve the site."

cd $WORK
python -m mkdocs serve

