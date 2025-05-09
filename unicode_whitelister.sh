#!/bin/bash

# Single whitelist file
WHITELIST_FILE=".unicode_whitelist.json"

# Create whitelist file if it doesn't exist
if [ ! -f "$WHITELIST_FILE" ]; then
    echo '{}' > "$WHITELIST_FILE"
fi

# Run the scan command and process each result
git grep --line-number -I -P "[^\x00-\x7F]" | grep -v -e "^electrum/locale/" -e "^electrum/wordlist/" -e "^fastlane/" | while read -r line; do
    # Parse the line: filename:line_number:content
    file=$(echo "$line" | cut -d':' -f1)
    line_num=$(echo "$line" | cut -d':' -f2)
    content=$(echo "$line" | cut -d':' -f3-)

    # Extract non-ASCII characters
    non_ascii=$(echo "$content" | grep -o -P "[^\x00-\x7F]")

    # Process each non-ASCII character
    while IFS= read -r char; do
        # Get unicode code point for the character
        hex_val=$(printf "%x" "'$char")

        # Check if the character exists in whitelist for this file
        # Use type checking to ensure we're dealing with arrays
        if jq -e "(.\"$file\" // []) | type == \"array\" and contains([\"$hex_val\"])" "$WHITELIST_FILE" > /dev/null; then
            # Character is whitelisted, skip it
            continue
        else
            # Report the finding
            echo "New Unicode character found: $file:$line_num - U+$hex_val"

            # Add to whitelist (only storing the hex value, not the line number)
            # Ensure we always have an array, using // [] to default to empty array if key doesn't exist
            jq --arg file "$file" --arg hex "$hex_val" \
               '.[$file] = ((.[$file] // []) | if type == "array" then . + [$hex] else [$hex] end)' \
               "$WHITELIST_FILE" > "${WHITELIST_FILE}.tmp" && mv "${WHITELIST_FILE}.tmp" "$WHITELIST_FILE"
        fi
    done <<< "$non_ascii"
done

echo "Scan complete. Whitelist updated in $WHITELIST_FILE file."
