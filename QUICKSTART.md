# Quick Start Guide - X DM Deleter Selenium Version

## ⚠️ Important: How X DM Deletion Works

X only allows deleting **entire conversations**, not individual messages.
When you delete a conversation, it disappears from your inbox permanently.
The other person's copy is unaffected.

---

## 🎯 5-Minute Setup

### 1. Install Chrome & Dependencies

```bash
# macOS
brew install --cask google-chrome
brew install chromedriver
pip3 install selenium

# Linux
sudo apt install chromium-browser chromium-chromedriver  # Ubuntu/Debian
sudo apt-get install chromium chromium-driver            # Kali Linux
pip3 install selenium

# Or just run:
./setup.sh
```

### 2. Configure Your Credentials

```bash
cp config_dm.example.json config_dm.json
nano config_dm.json
```

```json
{
  "username": "your_email_or_username",
  "password": "your_password",
  "headless": false
}
```

### 3. Test It (Dry Run)

```bash
python3 dm_deleter_selenium.py
```

**What you'll see:**
1. Browser window opens
2. Goes to X login page
3. Enters your username/password
4. Asks for 2FA code if needed
5. Navigates to Messages
6. Shows what would be deleted (nothing actually deleted)

### 4. Delete Conversations

```bash
python3 dm_deleter_selenium.py --execute
```

Type `DELETE ALL` to confirm.

---

## 🎓 Common Commands

```bash
# Delete everything (with confirmation)
python3 dm_deleter_selenium.py --execute

# Delete only first 20 conversations
python3 dm_deleter_selenium.py --execute --limit 20

# Delete conversations with a specific person
python3 dm_deleter_selenium.py --execute --participants "@handle" "Display Name"

# Delete conversations whose preview matches keywords
python3 dm_deleter_selenium.py --execute --keywords "spam" "promo" "deal"

# Dry run with limit (preview what would be deleted)
python3 dm_deleter_selenium.py --limit 10
```

---

## ⚠️ First-Time Tips

1. **Keep browser visible** (`headless: false`) for first run
2. **Watch what happens** - verify it's targeting the right conversations
3. **Have 2FA ready** if it's enabled on your account
4. **Always dry run first** before using --execute
5. **Check logs/** after the run to review the audit trail

---

## 🔐 Security Reminders

- ⚠️ Never commit `config_dm.json` (has your password!)
- ✅ It's in `.gitignore` automatically
- ✅ Use a strong, unique password
- ✅ Enable 2FA on your X account

---

## 🐛 Quick Troubleshooting

### Delete option not found
X changes their UI frequently. Check for tool updates or open a browser
manually, right-click a conversation, and note the exact menu text shown.

### Browser doesn't open
```bash
brew install chromedriver          # macOS
sudo apt install chromium-driver   # Kali Linux
```

### Login fails
- Double-check username/password in config_dm.json
- Watch for "unusual activity" prompts in the browser window
- Try logging in manually first, then re-run

### Smart quote errors in config
If you get JSON parse errors, check for curly quotes:
```bash
cat -A config_dm.json   # Smart quotes show as M-bM-^@M-^^ instead of "
```
Fix by retyping quotes manually in a plain text editor.

---

## 📊 What to Expect

**Speed:** ~8-12 conversations per minute (with default 2s delay)

**Logs:** See `logs/` directory after run
- `dm_deletions_TIMESTAMP.csv` - full audit trail with SHA-256 hashes
- `dm_audit_TIMESTAMP.log` - human-readable action log
- `dm_manifest_TIMESTAMP.json` - session summary
- `dm_deletions_TIMESTAMP.sha256` - log integrity hash

---

## 🆚 Companion Tool

This tool is the DM companion to `tweet_deleter_selenium.py`.
Both tools share the same:
- Config file format (separate files: config_dm.json / config_selenium.json)
- Forensic logging structure
- CLI argument conventions
- Setup and packaging
