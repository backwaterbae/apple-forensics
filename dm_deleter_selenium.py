#!/usr/bin/env python3
"""
Twitter/X DM Conversation Deletion Tool - Selenium Version
Browser automation version for deleting X.com direct message conversations.

NOTE: X only allows deleting entire conversations, not individual messages.
      This tool deletes conversations (threads) from your inbox.

Author: Digital Forensics Toolkit
License: MIT
"""

import time
import json
import sys
import csv
import hashlib
import argparse
from datetime import datetime, timezone
from pathlib import Path
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.action_chains import ActionChains
from selenium.common.exceptions import (
    TimeoutException,
    NoSuchElementException,
    StaleElementReferenceException,
    ElementClickInterceptedException
)

# =============================================================================
# CONFIGURATION
# =============================================================================

class Config:
    """Configuration management"""

    def __init__(self, config_file='config_dm.json'):
        self.config_file = config_file
        self.load_config()

    def load_config(self):
        """Load configuration from file"""
        if Path(self.config_file).exists():
            with open(self.config_file, 'r') as f:
                config = json.load(f)
                self.username         = config.get('username', '')
                self.password         = config.get('password', '')
                self.dry_run          = config.get('dry_run', True)
                self.delay            = config.get('delay_between_deletes', 2)
                self.headless         = config.get('headless', False)
                self.log_deletions    = config.get('log_deletions', True)
                self.log_dir          = config.get('log_directory', 'logs')
        else:
            print(f"⚠ Config file '{self.config_file}' not found")
            print("Please copy config_dm.example.json to config_dm.json")
            sys.exit(1)

# =============================================================================
# FORENSIC LOGGING
# =============================================================================

class ForensicLogger:
    """Handles forensic-grade logging with timestamps and hashing"""

    def __init__(self, log_dir='logs'):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)

        timestamp         = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.deletion_log = self.log_dir / f'dm_deletions_{timestamp}.csv'
        self.audit_log    = self.log_dir / f'dm_audit_{timestamp}.log'
        self.manifest     = self.log_dir / f'dm_manifest_{timestamp}.json'

        self._init_csv_log()

        self.manifest_data = {
            'session_start'          : datetime.now(timezone.utc).isoformat(),
            'session_id'             : hashlib.sha256(timestamp.encode()).hexdigest()[:16],
            'method'                 : 'selenium_browser_automation',
            'target'                 : 'dm_conversations',
            'conversations_processed': 0,
            'conversations_deleted'  : 0,
            'conversations_filtered' : 0,
            'errors'                 : 0,
            'filters_applied'        : []
        }

    def _init_csv_log(self):
        """Initialize CSV log with headers"""
        with open(self.deletion_log, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                'timestamp',
                'conversation_index',
                'participant_preview',
                'preview_text',
                'preview_hash',
                'action',
                'reason'
            ])

    def log_conversation(self, index, participant, preview, action, reason=''):
        """Log a conversation action with forensic details"""
        timestamp    = datetime.now(timezone.utc).isoformat()
        preview_hash = hashlib.sha256((participant + preview).encode()).hexdigest()

        with open(self.deletion_log, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                timestamp,
                index,
                participant,
                preview[:100],
                preview_hash,
                action,
                reason
            ])

        with open(self.audit_log, 'a') as f:
            f.write(f"[{timestamp}] {action}: [{index}] {participant} - {reason}\n")

    def update_manifest(self, key, value):
        """Update manifest data"""
        self.manifest_data[key] = value

    def finalize(self):
        """Finalize logs and create manifest"""
        self.manifest_data['session_end'] = datetime.now(timezone.utc).isoformat()

        with open(self.manifest, 'w') as f:
            json.dump(self.manifest_data, f, indent=2)

        with open(self.deletion_log, 'rb') as f:
            log_hash = hashlib.sha256(f.read()).hexdigest()

        hash_file = self.deletion_log.with_suffix('.sha256')
        with open(hash_file, 'w') as f:
            f.write(f"{log_hash}  {self.deletion_log.name}\n")

        print(f"\n📋 Logs saved to: {self.log_dir}")
        print(f"   - Deletion log : {self.deletion_log.name}")
        print(f"   - Audit log    : {self.audit_log.name}")
        print(f"   - Manifest     : {self.manifest.name}")
        print(f"   - Hash         : {hash_file.name}")

# =============================================================================
# CONVERSATION FILTERS
# =============================================================================

class ConversationFilters:
    """Filter DM conversations based on various criteria"""

    @staticmethod
    def by_participant(participant_text, names):
        """Filter conversations involving specific participants"""
        if not names:
            return True
        participant_lower = participant_text.lower()
        return any(name.lower() in participant_lower for name in names)

    @staticmethod
    def by_preview_keywords(preview_text, keywords, match_mode='any'):
        """Filter conversations whose preview contains keywords"""
        if not keywords:
            return True
        preview_lower = preview_text.lower()
        if match_mode == 'any':
            return any(kw.lower() in preview_lower for kw in keywords)
        elif match_mode == 'all':
            return all(kw.lower() in preview_lower for kw in keywords)
        return True

# =============================================================================
# BROWSER AUTOMATION
# =============================================================================

class XBrowser:
    """Handles X.com browser automation for DM deletion"""

    MESSAGES_URL = "https://x.com/messages"

    def __init__(self, config):
        self.config = config
        self.driver = None
        self.wait   = None

    def setup_driver(self):
        """Setup Chrome driver with appropriate options"""
        print("Setting up browser...")

        options = webdriver.ChromeOptions()

        if self.config.headless:
            options.add_argument('--headless=new')

        # Anti-detection measures
        options.add_argument('--disable-blink-features=AutomationControlled')
        options.add_experimental_option("excludeSwitches", ["enable-automation"])
        options.add_experimental_option('useAutomationExtension', False)
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument('--no-sandbox')
        options.add_argument('--window-size=1920,1080')
        options.add_argument(
            'user-agent=Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) '
            'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        )

        try:
            from selenium.webdriver.chrome.service import Service
            import shutil

            chromedriver_paths = [
                '/usr/bin/chromedriver',
                '/usr/local/bin/chromedriver',
                shutil.which('chromedriver')
            ]

            chromedriver_path = None
            for path in chromedriver_paths:
                if path and Path(path).exists():
                    chromedriver_path = path
                    break

            if chromedriver_path:
                service     = Service(chromedriver_path)
                self.driver = webdriver.Chrome(service=service, options=options)
            else:
                self.driver = webdriver.Chrome(options=options)

            self.driver.execute_script(
                "Object.defineProperty(navigator, 'webdriver', {get: () => undefined})"
            )
            self.wait = WebDriverWait(self.driver, 10)
            print("✓ Browser ready")
            return True

        except Exception as e:
            print(f"✗ Failed to setup browser: {e}")
            print("\nMake sure Chrome and chromedriver are installed:")
            print("  - Kali Linux:  sudo apt-get install chromium chromium-driver")
            print("  - Ubuntu:      sudo apt install chromium-browser chromium-chromedriver")
            print("  - macOS:       brew install chromedriver")
            return False

    def login(self):
        """Login to X.com"""
        print("\n" + "=" * 70)
        print("LOGGING IN TO X.COM")
        print("=" * 70)

        try:
            self.driver.get("https://x.com/login")
            time.sleep(3)

            # Enter username
            print("Entering username...")
            username_input = self.wait.until(
                EC.presence_of_element_located((By.CSS_SELECTOR, 'input[autocomplete="username"]'))
            )
            username_input.send_keys(self.config.username)
            username_input.send_keys(Keys.RETURN)
            time.sleep(2)

            # Check for unusual activity prompt
            try:
                self.driver.find_element(By.XPATH, "//*[contains(text(), 'unusual')]")
                print("\n⚠️  X detected unusual activity")
                input("Complete the verification in the browser, then press Enter...")
            except NoSuchElementException:
                pass

            # Enter password
            print("Entering password...")
            password_input = self.wait.until(
                EC.presence_of_element_located((By.CSS_SELECTOR, 'input[name="password"]'))
            )
            password_input.send_keys(self.config.password)
            password_input.send_keys(Keys.RETURN)
            time.sleep(3)

            # Handle 2FA
            try:
                twofa_input = self.driver.find_element(
                    By.CSS_SELECTOR, 'input[data-testid="ocfEnterTextTextInput"]'
                )
                print("\n🔐 Two-Factor Authentication Required")
                code = input("Enter your 2FA code: ")
                twofa_input.send_keys(code)
                twofa_input.send_keys(Keys.RETURN)
                time.sleep(3)
            except NoSuchElementException:
                pass

            time.sleep(2)
            if "home" in self.driver.current_url.lower() or "x.com" in self.driver.current_url:
                print("✓ Login successful!")
                return True
            else:
                print("✗ Login may have failed - check browser")
                return False

        except Exception as e:
            print(f"✗ Login error: {e}")
            return False

    def go_to_messages(self):
        """Navigate to the Messages inbox"""
        print("\nNavigating to Messages...")
        try:
            self.driver.get(self.MESSAGES_URL)
            time.sleep(3)

            # Confirm messages loaded
            self.wait.until(
                EC.presence_of_element_located((
                    By.XPATH,
                    "//div[@data-testid='conversation'] | "
                    "//section[@role='region'] | "
                    "//div[contains(@aria-label,'Messages')]"
                ))
            )
            print("✓ Messages loaded")
            return True

        except TimeoutException:
            print("⚠️  Could not confirm Messages loaded - proceeding anyway")
            return True
        except Exception as e:
            print(f"✗ Error navigating to Messages: {e}")
            return False

    def get_visible_conversations(self):
        """Return all currently visible conversation rows"""
        selectors = [
            "div[data-testid='conversation']",
            "div[role='row']",
            "li[role='listitem']"
        ]
        for selector in selectors:
            elems = self.driver.find_elements(By.CSS_SELECTOR, selector)
            if elems:
                return elems
        return []

    def extract_conversation_info(self, elem):
        """Extract participant name and preview text from a conversation element"""
        participant = "Unknown"
        preview     = ""

        try:
            # Participant name - try multiple selectors X has used
            for sel in [
                "span[data-testid='User-Name']",
                "div[dir='ltr'] > span",
                "span.css-901oao"
            ]:
                try:
                    participant = elem.find_element(By.CSS_SELECTOR, sel).text.strip()
                    if participant:
                        break
                except NoSuchElementException:
                    continue
        except Exception:
            pass

        try:
            # Message preview text
            for sel in [
                "span[data-testid='tweetText']",
                "div[data-testid='messageEntry']",
                "div[dir='auto'] span"
            ]:
                try:
                    preview = elem.find_element(By.CSS_SELECTOR, sel).text.strip()
                    if preview:
                        break
                except NoSuchElementException:
                    continue
        except Exception:
            pass

        return participant, preview

    def delete_conversation(self, elem, dry_run=False):
        """
        Delete a single conversation.
        X requires: right-click (or ···) → 'Delete conversation' → confirm.
        Returns True on success.
        """
        if dry_run:
            return True

        try:
            self.driver.execute_script("arguments[0].scrollIntoView(true);", elem)
            time.sleep(0.3)

            # --- Try right-click context menu first ---
            ActionChains(self.driver).context_click(elem).perform()
            time.sleep(0.7)

            # Look for "Delete conversation" in menu
            delete_option = None
            for xpath in [
                "//span[contains(text(), 'Delete conversation')]",
                "//div[@role='menuitem'][contains(., 'Delete conversation')]",
                "//a[@role='menuitem'][contains(., 'Delete')]"
            ]:
                try:
                    delete_option = WebDriverWait(self.driver, 3).until(
                        EC.element_to_be_clickable((By.XPATH, xpath))
                    )
                    break
                except TimeoutException:
                    continue

            # --- Fallback: look for ··· button inside the row ---
            if not delete_option:
                self.driver.find_element(By.TAG_NAME, "body").send_keys(Keys.ESCAPE)
                time.sleep(0.3)

                for sel in [
                    "[data-testid='dmDrawerHeader'] button",
                    "[aria-label='More']",
                    "div[role='button'][aria-haspopup='menu']"
                ]:
                    try:
                        more_btn = elem.find_element(By.CSS_SELECTOR, sel)
                        self.driver.execute_script("arguments[0].click();", more_btn)
                        time.sleep(0.5)
                        break
                    except NoSuchElementException:
                        continue

                for xpath in [
                    "//span[contains(text(), 'Delete conversation')]",
                    "//div[@role='menuitem'][contains(., 'Delete')]"
                ]:
                    try:
                        delete_option = WebDriverWait(self.driver, 3).until(
                            EC.element_to_be_clickable((By.XPATH, xpath))
                        )
                        break
                    except TimeoutException:
                        continue

            if not delete_option:
                print("  ⚠️  Could not find delete option in menu")
                self.driver.find_element(By.TAG_NAME, "body").send_keys(Keys.ESCAPE)
                return False

            delete_option.click()
            time.sleep(0.5)

            # --- Confirm deletion dialog ---
            for sel in [
                "[data-testid='confirmationSheetConfirm']",
                "button[data-testid='confirmationSheetConfirm']"
            ]:
                try:
                    confirm = WebDriverWait(self.driver, 5).until(
                        EC.element_to_be_clickable((By.CSS_SELECTOR, sel))
                    )
                    confirm.click()
                    time.sleep(1)
                    return True
                except TimeoutException:
                    continue

            # Fallback confirm - find any "Delete" button in a dialog
            try:
                confirm = WebDriverWait(self.driver, 5).until(
                    EC.element_to_be_clickable((
                        By.XPATH,
                        "//div[@role='alertdialog']//button[contains(., 'Delete')]"
                    ))
                )
                confirm.click()
                time.sleep(1)
                return True
            except TimeoutException:
                print("  ⚠️  Confirmation dialog not found")
                return False

        except Exception as e:
            print(f"\n  ⚠️  Error during deletion: {e}")
            try:
                self.driver.find_element(By.TAG_NAME, "body").send_keys(Keys.ESCAPE)
            except Exception:
                pass
            return False

    def close(self):
        """Close the browser"""
        if self.driver:
            self.driver.quit()

# =============================================================================
# DM DELETER
# =============================================================================

class SeleniumDMDeleter:
    """Main DM conversation deletion handler"""

    def __init__(self, config):
        self.config          = config
        self.browser         = XBrowser(config)
        self.logger          = None
        self.filters_active  = {}

    def get_user_confirmation(self, item_desc):
        """Get explicit user confirmation before any deletion"""
        print(f"\n{'=' * 70}")
        print(f"⚠  WARNING: About to delete DM conversations - {item_desc}")
        print(f"⚠  This action is PERMANENT and IRREVERSIBLE")
        print(f"⚠  X deletes the ENTIRE conversation, not individual messages")

        if self.filters_active:
            print(f"\n   Active filters:")
            for name, desc in self.filters_active.items():
                print(f"   - {name}: {desc}")

        print(f"{'=' * 70}\n")
        response = input("Type 'DELETE ALL' to confirm: ")
        return response == "DELETE ALL"

    def delete_dms(self, dry_run=True, limit=None, participants=None,
                   keywords=None, keyword_mode='any'):
        """
        Delete DM conversations with optional filtering.

        Parameters
        ----------
        dry_run      : bool   - If True, log only; do not actually delete
        limit        : int    - Max conversations to delete (None = all)
        participants : list   - Only delete convos with these participants
        keywords     : list   - Only delete convos whose preview matches
        keyword_mode : str    - 'any' or 'all' for keyword matching
        """

        # Initialize logger
        if self.config.log_deletions:
            self.logger = ForensicLogger(self.config.log_dir)

        # Track active filters
        if participants:
            self.filters_active['Participants'] = ', '.join(participants)
            if self.logger:
                self.logger.manifest_data['filters_applied'].append(
                    f"participants: {participants}"
                )
        if keywords:
            self.filters_active['Keywords'] = f"{keyword_mode.upper()}: {', '.join(keywords)}"
            if self.logger:
                self.logger.manifest_data['filters_applied'].append(
                    f"keywords: {keywords} (mode: {keyword_mode})"
                )
        if limit:
            self.filters_active['Limit'] = str(limit)

        # Setup browser
        if not self.browser.setup_driver():
            return

        # Login
        if not self.browser.login():
            print("\n✗ Login failed. Cannot proceed.")
            self.browser.close()
            return

        # Navigate to Messages
        if not self.browser.go_to_messages():
            print("\n✗ Could not access Messages. Cannot proceed.")
            self.browser.close()
            return

        time.sleep(2)

        # Dry-run header
        mode = 'DRY RUN MODE' if dry_run else '🔥 DELETION MODE 🔥'
        limit_str = str(limit) if limit else 'all'
        print(f"\n{mode} - Will process up to {limit_str} conversation(s)\n")

        deleted_count  = 0
        filtered_count = 0
        error_count    = 0
        index          = 0
        consecutive_fails = 0

        while True:
            # Respect limit
            if limit and deleted_count >= limit:
                print(f"\nLimit of {limit} reached.")
                break

            # Grab the current first conversation (list refreshes after each delete)
            conversations = self.browser.get_visible_conversations()

            if not conversations:
                print("\nNo more conversations visible. Done.")
                break

            elem = conversations[0]
            index += 1

            try:
                participant, preview = self.browser.extract_conversation_info(elem)
                display = f"[{index}] {participant} — {preview[:60]}"

                # Apply filters
                passes = True
                reason = ""

                if participants and not ConversationFilters.by_participant(participant, participants):
                    passes = False
                    reason = "Participant not in filter list"

                if passes and keywords and not ConversationFilters.by_preview_keywords(
                        preview, keywords, keyword_mode):
                    passes = False
                    reason = "No keyword match in preview"

                if not passes:
                    filtered_count += 1
                    print(f"  ⤷ FILTERED  {display}  ({reason})")
                    if self.logger:
                        self.logger.log_conversation(index, participant, preview,
                                                     'FILTERED', reason)
                    # Scroll past this conversation to expose the next one
                    self.browser.driver.execute_script(
                        "arguments[0].scrollIntoView(false);", elem
                    )
                    time.sleep(0.5)
                    # Can't easily skip without clicking - note and break
                    # Filtering with scroll is tricky; warn user
                    print("  ⚠️  Skipping filtered conversations requires scrolling - "
                          "tool will stop here to avoid deleting wrong conversations.")
                    print("     Re-run with more specific filters or without --participants/--keywords "
                          "to delete all conversations.")
                    break

                if dry_run:
                    print(f"  [DRY RUN] Would delete {display}")
                    deleted_count += 1
                    if self.logger:
                        self.logger.log_conversation(index, participant, preview,
                                                     'DRY_RUN_DELETE', 'Would be deleted')
                    # In dry run, move past this element by scrolling
                    self.browser.driver.execute_script(
                        "arguments[0].scrollIntoView(false);", elem
                    )
                    time.sleep(0.3)
                    # After a few dry-run steps the list won't change; break to avoid loop
                    if deleted_count >= (limit or 25):
                        break
                    continue

                # --- Real deletion ---
                success = self.browser.delete_conversation(elem, dry_run=False)

                if success:
                    deleted_count += 1
                    consecutive_fails = 0
                    print(f"  ✓ Deleted     {display}")
                    if self.logger:
                        self.logger.log_conversation(index, participant, preview,
                                                     'DELETED', 'Successfully deleted')
                    time.sleep(self.config.delay)
                else:
                    error_count += 1
                    consecutive_fails += 1
                    print(f"  ✗ Failed      {display}")
                    if self.logger:
                        self.logger.log_conversation(index, participant, preview,
                                                     'ERROR', 'Deletion failed')

                    if consecutive_fails >= 3:
                        print("\n  3 consecutive failures — pausing 15s and refreshing...")
                        time.sleep(15)
                        self.browser.driver.get(XBrowser.MESSAGES_URL)
                        time.sleep(3)
                        consecutive_fails = 0

            except StaleElementReferenceException:
                print(f"  ⚠️  Element went stale, retrying...")
                time.sleep(1)
                continue
            except Exception as e:
                print(f"\n  ✗ Unexpected error: {e}")
                error_count += 1
                consecutive_fails += 1
                time.sleep(1)

        # Close browser
        self.browser.close()

        # Finalize logging
        if self.logger:
            self.logger.update_manifest('conversations_processed',
                                        deleted_count + filtered_count + error_count)
            self.logger.update_manifest('conversations_deleted', deleted_count)
            self.logger.update_manifest('conversations_filtered', filtered_count)
            self.logger.update_manifest('errors', error_count)
            self.logger.finalize()

        # Summary
        print(f"\n{'=' * 70}")
        print(f"SUMMARY")
        print(f"{'=' * 70}")
        print(f"Deleted     : {deleted_count}")
        print(f"Filtered out: {filtered_count}")
        print(f"Errors      : {error_count}")
        print(f"{'=' * 70}\n")

# =============================================================================
# COMMAND LINE INTERFACE
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='Twitter/X DM Conversation Deletion Tool - Selenium Version',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
NOTE:
  X only lets you delete entire conversations, not individual messages.

Examples:
  # Dry run (safe, default)
  python3 dm_deleter_selenium.py

  # Delete all conversations (with confirmation)
  python3 dm_deleter_selenium.py --execute

  # Delete only first 20 conversations
  python3 dm_deleter_selenium.py --execute --limit 20

  # Delete conversations with a specific person
  python3 dm_deleter_selenium.py --execute --participants "John Doe" "@handle"

  # Delete conversations whose preview contains keywords
  python3 dm_deleter_selenium.py --execute --keywords "promo" "discount"
        """
    )

    parser.add_argument('--config', default='config_dm.json',
                        help='Config file path (default: config_dm.json)')
    parser.add_argument('--execute', action='store_true',
                        help='Actually delete conversations (dry run by default)')
    parser.add_argument('--limit', type=int, metavar='N',
                        help='Max number of conversations to delete')
    parser.add_argument('--participants', nargs='+', metavar='NAME',
                        help='Only delete conversations with these participant names/handles')
    parser.add_argument('--keywords', nargs='+', metavar='KEYWORD',
                        help='Only delete conversations whose preview contains these keywords')
    parser.add_argument('--keyword-mode', choices=['any', 'all'], default='any',
                        help='Match ANY or ALL keywords in preview (default: any)')
    parser.add_argument('--no-log', action='store_true',
                        help='Disable forensic logging')

    args = parser.parse_args()

    print("=" * 70)
    print("Twitter/X DM Conversation Deletion Tool - Selenium Version")
    print("=" * 70)
    print("⚠  NOTE: X deletes entire conversations, not individual messages")
    print("=" * 70)

    config = Config(args.config)

    if args.no_log:
        config.log_deletions = False

    deleter = SeleniumDMDeleter(config)

    dry_run = not args.execute or config.dry_run

    if dry_run:
        print("\n⚠ DRY RUN MODE - No conversations will be deleted")
        print("Use --execute flag to actually delete conversations\n")

    # Confirmation for real deletions
    if not dry_run:
        limit_str = f"up to {args.limit}" if args.limit else "ALL"
        if not deleter.get_user_confirmation(limit_str):
            print("\nAborted.")
            sys.exit(0)

    deleter.delete_dms(
        dry_run      = dry_run,
        limit        = args.limit,
        participants = args.participants,
        keywords     = args.keywords,
        keyword_mode = args.keyword_mode
    )

if __name__ == "__main__":
    main()
