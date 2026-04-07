#!/bin/bash

# ─────────────────────────────────────────────
#  ProbePoint - Custom Wordlist Generator
# ─────────────────────────────────────────────

TARGET_URL="$1"

if [ -z "$TARGET_URL" ]; then
    echo "[!] Usage: ./generate_wordlist.sh <target_url>"
    echo "    Example: ./generate_wordlist.sh http://192.168.1.143"
    exit 1
fi

TARGET_URL="${TARGET_URL%/}"

STOPWORDS="stopwords.txt"
ROCKYOU_SLIM="rockyou_slim.txt"
DIRB_WORDLIST="/usr/share/dirb/wordlists/big.txt"

CEWL_RAW="cewl_raw.txt"
CEWL_FILTERED="cewl_filtered.txt"
CEWL_MANGLED="cewl_mangled.txt"
FINAL_OUTPUT="final_wordlist.txt"

# ─────────────────────────────────────────────
#  Sanity Checks
# ─────────────────────────────────────────────

if [ ! -f "$STOPWORDS" ]; then
    echo "[!] stopwords.txt not found in current directory. Exiting."
    exit 1
fi

if [ ! -f "$ROCKYOU_SLIM" ]; then
    echo "[!] rockyou_slim.txt not found. Run slim_rockyou.sh first. Exiting."
    exit 1
fi

if ! command -v gobuster &> /dev/null; then
    echo "[!] gobuster not found. Install it with: sudo apt install gobuster"
    exit 1
fi

# ─────────────────────────────────────────────
#  Step 1: Run gobuster, parse found URLs
# ─────────────────────────────────────────────

echo "[*] Running gobuster against $TARGET_URL..."
FOUND_PAGES=$(gobuster dir -u "$TARGET_URL" -w "$DIRB_WORDLIST" \
    --status-codes 200 --status-codes-blacklist "" \
    -x html,php,txt -r -q --no-error 2>/dev/null \
    | awk '{print $1}' | sed "s|^|$TARGET_URL/|" | sed "s|//|/|2g")

if [ -z "$FOUND_PAGES" ]; then
    echo "[!] gobuster found no pages. Falling back to target root only."
    FOUND_PAGES="$TARGET_URL"
fi

echo "[+] Pages found:"
echo "$FOUND_PAGES"

# ─────────────────────────────────────────────
#  Step 2: Run CeWL on each discovered URL
# ─────────────────────────────────────────────

echo "[*] Running CeWL on discovered pages (min word length: 4, depth: 1)..."
> "$CEWL_RAW"

while IFS= read -r page; do
    echo "    [~] Scraping: $page"
    cewl "$page" -d 1 -m 4 --lowercase >> "$CEWL_RAW" 2>/dev/null
done <<< "$FOUND_PAGES"

echo "[+] CeWL raw word count: $(wc -l < "$CEWL_RAW")"

# ─────────────────────────────────────────────
#  Step 3: Filter CeWL output against stopwords
# ─────────────────────────────────────────────

echo "[*] Filtering CeWL output against stopwords..."
comm -23 <(sort "$CEWL_RAW") <(sort "$STOPWORDS") > "$CEWL_FILTERED"

echo "[+] CeWL filtered word count: $(wc -l < "$CEWL_FILTERED")"

# ─────────────────────────────────────────────
#  Step 4: Mangle CeWL output with john best64
#          and append ! variants
# ─────────────────────────────────────────────

echo "[*] Mangling CeWL output with john best64 rules..."
{
    john --wordlist="$CEWL_FILTERED" --rules=best64 --stdout 2>/dev/null
    awk '{print $0"!"}' "$CEWL_FILTERED"
} | awk 'length($0) <= 8' | sort -u > "$CEWL_MANGLED"

echo "[+] Mangled word count: $(wc -l < "$CEWL_MANGLED")"

# ─────────────────────────────────────────────
#  Step 5: Combine rockyou_slim + mangled CeWL
#          then trim final list to max 8 chars
# ─────────────────────────────────────────────

echo "[*] Combining rockyou_slim.txt and mangled CeWL output..."
sort -u "$ROCKYOU_SLIM" "$CEWL_MANGLED" | awk 'length($0) <= 8' > "$FINAL_OUTPUT"

# ─────────────────────────────────────────────
#  Step 6: Cleanup intermediate files
# ─────────────────────────────────────────────

echo "[*] Cleaning up intermediate files..."
rm -f "$CEWL_RAW" "$CEWL_FILTERED" "$CEWL_MANGLED" test.txt

echo ""
echo "═══════════════════════════════════════════"
echo "[+] Wordlist generation complete!"
echo "    Output: $FINAL_OUTPUT"
echo "    Final entry count: $(wc -l < "$FINAL_OUTPUT")"
echo "═══════════════════════════════════════════"
