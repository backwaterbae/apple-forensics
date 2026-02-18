# Quick Start Guide — X DM Deleter API Version v2.0.0

## ⚠️ Important Notes

- No browser required — pure API, no username/password stored
- X has no "delete conversation" endpoint; this deletes all messages in each
  conversation (same effect — conversation disappears from your inbox)
- DM **listing** requires **X API Basic tier ($100/mo)**
- Message **deletion** uses the v1.1 endpoint (included in Basic+)
- Deleted messages are removed from YOUR view only — recipient's copy remains

---

## 🎯 5-Minute Setup

### 1. Install dependency

```bash
pip3 install tweepy
# or just run:
./setup.sh
```

### 2. Get your API keys

1. Go to https://developer.twitter.com/en/portal/dashboard
2. Open (or create) your app
3. **Set app permissions: Read + Write + Direct Messages** ← required
4. Go to **Keys & Tokens**
5. Generate **Access Token & Secret** (you need all 4 keys)

### 3. Configure

```bash
cp config_dm.example.json config_dm.json
nano config_dm.json
```

```json
{
  "api_key":             "xxxxxxxxxxxxxxxxxxxxxxxxx",
  "api_key_secret":      "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  "access_token":        "xxxxxxxxx-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  "access_token_secret": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  "dry_run":             true,
  "delay_between_deletes": 1.0
}
```

### 4. Dry run (safe — nothing deleted)

```bash
python3 dm_deleter_selenium.py
```

### 5. Real deletion

```bash
python3 dm_deleter_selenium.py --execute
```

Type `DELETE ALL` when prompted.

---

## 🎓 Common Commands

```bash
# Dry run — show what would be deleted
python3 dm_deleter_selenium.py

# Delete all conversations
python3 dm_deleter_selenium.py --execute

# Delete first 20 conversations only
python3 dm_deleter_selenium.py --execute --limit 20

# Delete conversations with specific users (by X user ID)
python3 dm_deleter_selenium.py --execute --participant-ids 123456789

# Disable forensic logging
python3 dm_deleter_selenium.py --execute --no-log
```

---

## 🔐 Security Notes

- `config_dm.json` is in `.gitignore` — never commit it
- If keys are compromised: portal → Keys & Tokens → Revoke
- No username or password is ever stored or transmitted

---

## 📊 Logs

Each session produces in `logs/`:

| File | Contents |
|------|----------|
| `dm_deletions_TIMESTAMP.csv` | Full audit trail per message |
| `dm_audit_TIMESTAMP.log` | Human-readable action log |
| `dm_manifest_TIMESTAMP.json` | Session summary |
| `dm_deletions_TIMESTAMP.sha256` | Log integrity hash |

---

## 🐛 Troubleshooting

### 403 Forbidden on DM listing
You need **X API Basic tier** ($100/mo). The free tier does not include
DM read endpoints. Upgrade at https://developer.twitter.com/en/portal/products

### 401 Unauthorized
- Double-check all 4 keys are correct
- Make sure Access Token/Secret match your account (not just the app)
- Verify app permissions include Direct Messages, then regenerate tokens

### Smart quote errors in config
```bash
cat -A config_dm.json   # smart quotes show as M-bM-^@M-^^ instead of "
```
Fix by retyping quotes in a plain text editor.

### "Only deletes my view" — is that expected?
Yes. X's platform limitation — the API can only remove messages from the
authenticated user's view. This matches what the web UI does when you
"Delete conversation."

---

## 🆚 vs Selenium Version

| | Selenium version | API version (this) |
|--|--|--|
| Auth | username + password | 4 API keys |
| Browser | Required | Not needed |
| Speed | ~8-12 conversations/min | Faster, no UI wait |
| Reliability | Breaks when X changes UI | Stable API |
| Tier needed | Any (uses browser session) | Basic ($100/mo) |
| Credentials stored | Password in config | API keys only |

---

## 🔗 Resources

- X Developer Portal: https://developer.twitter.com/en/portal/dashboard
- API pricing: https://developer.twitter.com/en/products/twitter-api
- tweepy docs: https://docs.tweepy.org
