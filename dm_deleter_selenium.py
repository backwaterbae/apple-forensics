#!/usr/bin/env python3
"""
Twitter/X DM Conversation Deletion Tool - API Version
Authenticates via OAuth 1.0a (API keys — no username/password stored).
Uses X API v2 to list DM conversations and v1.1 to delete individual messages.

NOTE: X has no "delete entire conversation" API endpoint.
      This tool deletes all messages within each conversation,
      which removes the conversation from your inbox.

NOTE: DM listing endpoints require X API Basic tier ($100/mo) or higher.
      Message deletion (v1.1) works on Basic tier and above.

Usage:
    python3 dm_deleter_selenium.py                        # dry run (safe)
    python3 dm_deleter_selenium.py --execute              # delete all
    python3 dm_deleter_selenium.py --execute --limit 20   # delete 20 conversations

Author: Digital Forensics Toolkit
Version: 2.0.0
License: MIT
"""

# Standard library
import sys
import json
import csv
import hashlib
import argparse
import time
import logging
from datetime import datetime, timezone
from pathlib import Path

# Third-party
try:
    import tweepy
except ImportError:
    print("✗ tweepy not installed. Run: pip3 install tweepy")
    sys.exit(1)

# =============================================================================
# LOGGING SETUP
# =============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)
log = logging.getLogger(__name__)

# =============================================================================
# CONFIGURATION
# =============================================================================

class Config:
    """
    Load and validate API credentials from config file.

    Config file format (config_dm.json):
    {
        "api_key":             "...",
        "api_key_secret":      "...",
        "access_token":        "...",
        "access_token_secret": "...",
        "dry_run":             true,
        "delay_between_deletes": 1.0,
        "log_deletions":       true,
        "log_directory":       "logs"
    }

    Get your keys at: https://developer.twitter.com/en/portal/dashboard
    Required app permissions: Read + Write + Direct Messages
    """

    REQUIRED_KEYS = ["api_key", "api_key_secret", "access_token", "access_token_secret"]

    def __init__(self, config_file: str = "config_dm.json"):
        self.config_file = config_file
        self._load()

    def _load(self):
        """Load configuration from JSON file."""
        path = Path(self.config_file)
        if not path.exists():
            print(f"✗ Config file '{self.config_file}' not found.")
            print("  Copy config_dm.example.json → config_dm.json and add your API keys.")
            sys.exit(1)

        try:
            with open(path, "r") as f:
                cfg = json.load(f)
        except json.JSONDecodeError as e:
            print(f"✗ JSON parse error in {self.config_file}: {e}")
            print("  Tip: check for smart/curly quotes — run: cat -A config_dm.json")
            sys.exit(1)

        # Validate required keys
        missing = [k for k in self.REQUIRED_KEYS if not cfg.get(k)]
        if missing:
            print(f"✗ Missing required config keys: {', '.join(missing)}")
            sys.exit(1)

        self.api_key             = cfg["api_key"]
        self.api_key_secret      = cfg["api_key_secret"]
        self.access_token        = cfg["access_token"]
        self.access_token_secret = cfg["access_token_secret"]
        self.dry_run             = cfg.get("dry_run", True)
        self.delay               = float(cfg.get("delay_between_deletes", 1.0))
        self.log_deletions       = cfg.get("log_deletions", True)
        self.log_dir             = cfg.get("log_directory", "logs")


# =============================================================================
# FORENSIC LOGGING
# =============================================================================

class ForensicLogger:
    """
    Forensic-grade session logging.

    Produces per-session:
      dm_deletions_TIMESTAMP.csv    — full audit trail
      dm_audit_TIMESTAMP.log        — human-readable action log
      dm_manifest_TIMESTAMP.json    — session metadata
      dm_deletions_TIMESTAMP.sha256 — log integrity hash
    """

    def __init__(self, log_dir: str = "logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)

        ts                = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.deletion_log = self.log_dir / f"dm_deletions_{ts}.csv"
        self.audit_log    = self.log_dir / f"dm_audit_{ts}.log"
        self.manifest     = self.log_dir / f"dm_manifest_{ts}.json"

        self._init_csv()

        self.manifest_data = {
            "session_start"          : datetime.now(timezone.utc).isoformat(),
            "session_id"             : hashlib.sha256(ts.encode()).hexdigest()[:16],
            "method"                 : "x_api_v2_oauth1",
            "target"                 : "dm_conversations",
            "conversations_processed": 0,
            "messages_deleted"       : 0,
            "conversations_skipped"  : 0,
            "errors"                 : 0,
            "filters_applied"        : []
        }

    def _init_csv(self):
        """Write CSV header row."""
        with open(self.deletion_log, "w", newline="") as f:
            csv.writer(f).writerow([
                "timestamp",
                "conversation_id",
                "message_id",
                "sender_id",
                "created_at",
                "text_preview",
                "text_hash",
                "action",
                "reason"
            ])

    def log_message(
        self,
        conversation_id: str,
        message_id: str,
        sender_id: str,
        created_at: str,
        text: str,
        action: str,
        reason: str = ""
    ):
        """Log a single message action with forensic detail."""
        ts           = datetime.now(timezone.utc).isoformat()
        preview      = text[:100] + "..." if len(text) > 100 else text
        text_hash    = hashlib.sha256(text.encode()).hexdigest()

        with open(self.deletion_log, "a", newline="") as f:
            csv.writer(f).writerow([
                ts, conversation_id, message_id, sender_id,
                created_at, preview, text_hash, action, reason
            ])

        with open(self.audit_log, "a") as f:
            f.write(f"[{ts}] {action}: conv={conversation_id} msg={message_id} — {reason}\n")

    def update_manifest(self, key: str, value):
        self.manifest_data[key] = value

    def finalize(self):
        """Write manifest and compute log integrity hash."""
        self.manifest_data["session_end"] = datetime.now(timezone.utc).isoformat()

        with open(self.manifest, "w") as f:
            json.dump(self.manifest_data, f, indent=2)

        with open(self.deletion_log, "rb") as f:
            log_hash = hashlib.sha256(f.read()).hexdigest()

        hash_file = self.deletion_log.with_suffix(".sha256")
        with open(hash_file, "w") as f:
            f.write(f"{log_hash}  {self.deletion_log.name}\n")

        print(f"\n📋 Logs saved to: {self.log_dir}/")
        print(f"   Deletion log : {self.deletion_log.name}")
        print(f"   Audit log    : {self.audit_log.name}")
        print(f"   Manifest     : {self.manifest.name}")
        print(f"   Hash         : {hash_file.name}")


# =============================================================================
# CONVERSATION FILTERS
# =============================================================================

class ConversationFilters:
    """Optional filters applied before deletion."""

    @staticmethod
    def by_participant(participant_ids: list, target_ids: list) -> bool:
        """
        Return True if any target user ID appears in this conversation.

        Args:
            participant_ids: list of user ID strings in the conversation
            target_ids: user IDs to match against

        Returns:
            bool: True if conversation includes a target participant
        """
        if not target_ids:
            return True
        return any(uid in participant_ids for uid in target_ids)


# =============================================================================
# X API CLIENT
# =============================================================================

class XApiClient:
    """
    Wraps Tweepy for X API v2 DM operations.

    Authentication: OAuth 1.0a (User Context) — required for DM access.
    Listing:        GET /2/dm_events          — requires Basic tier+
    Deletion:       DELETE direct_messages/events/destroy (v1.1)
    """

    def __init__(self, config: Config):
        self.config = config
        self.client_v2 = None   # tweepy.Client  (v2 endpoints)
        self.api_v1    = None   # tweepy.API     (v1.1 endpoints)
        self.me        = None   # authenticated user object

    def connect(self) -> bool:
        """
        Authenticate with X API and verify credentials.

        Returns:
            bool: True if authentication succeeded
        """
        print("Connecting to X API...")
        try:
            # v2 client — OAuth 1.0a user context
            self.client_v2 = tweepy.Client(
                consumer_key        = self.config.api_key,
                consumer_secret     = self.config.api_key_secret,
                access_token        = self.config.access_token,
                access_token_secret = self.config.access_token_secret,
                wait_on_rate_limit  = True
            )

            # v1.1 API — needed for message deletion endpoint
            auth = tweepy.OAuth1UserHandler(
                consumer_key        = self.config.api_key,
                consumer_secret     = self.config.api_key_secret,
                access_token        = self.config.access_token,
                access_token_secret = self.config.access_token_secret
            )
            self.api_v1 = tweepy.API(auth, wait_on_rate_limit=True)

            # Verify credentials
            me = self.client_v2.get_me()
            if not me or not me.data:
                print("✗ Could not retrieve authenticated user. Check your API keys.")
                return False

            self.me = me.data
            print(f"✓ Authenticated as @{self.me.username} (ID: {self.me.id})")
            return True

        except tweepy.errors.Unauthorized:
            print("✗ Authentication failed — check your API keys and tokens.")
            print("  Make sure your app has 'Read + Write + Direct Messages' permissions.")
            return False
        except Exception as e:
            print(f"✗ Connection error: {e}")
            return False

    def get_dm_conversations(self) -> list:
        """
        Retrieve all DM conversations for the authenticated user.

        Uses GET /2/dm_events (Basic tier required).
        Returns conversations grouped by dm_conversation_id.

        Returns:
            list of dicts: [{"id": str, "participant_ids": list, "messages": list}]
        """
        print("\nFetching DM conversations...")
        conversations = {}

        try:
            paginator = tweepy.Paginator(
                self.client_v2.get_dm_events,
                dm_event_fields=["id", "text", "sender_id", "created_at",
                                 "dm_conversation_id", "participant_ids"],
                expansions=["sender_id"],
                max_results=100
            )

            total = 0
            for page in paginator:
                if not page.data:
                    continue
                for event in page.data:
                    cid = event.dm_conversation_id
                    if cid not in conversations:
                        conversations[cid] = {
                            "id"             : cid,
                            "participant_ids": getattr(event, "participant_ids", []),
                            "messages"       : []
                        }
                    conversations[cid]["messages"].append({
                        "id"        : event.id,
                        "text"      : getattr(event, "text", ""),
                        "sender_id" : str(getattr(event, "sender_id", "")),
                        "created_at": str(getattr(event, "created_at", ""))
                    })
                    total += 1
                print(f"\r  Retrieved {total} messages across "
                      f"{len(conversations)} conversations...", end="", flush=True)

            print(f"\n✓ Found {len(conversations)} conversations ({total} total messages)")
            return list(conversations.values())

        except tweepy.errors.Forbidden as e:
            print(f"\n✗ 403 Forbidden — DM listing requires X API Basic tier ($100/mo).")
            print(f"  Details: {e}")
            return []
        except tweepy.errors.TooManyRequests:
            print("\n⚠️  Rate limit hit — tweepy will auto-retry (wait_on_rate_limit=True)")
            return []
        except Exception as e:
            print(f"\n✗ Error fetching conversations: {e}")
            return []

    def delete_message(self, message_id: str) -> bool:
        """
        Delete a single DM message via v1.1 endpoint.

        Uses DELETE direct_messages/events/destroy.
        Only deletes from YOUR view (X's limitation).

        Args:
            message_id: ID of the message event to delete

        Returns:
            bool: True on success
        """
        try:
            self.api_v1.delete_direct_message(message_id)
            return True
        except tweepy.errors.NotFound:
            # Already deleted or never existed
            return True
        except tweepy.errors.TooManyRequests:
            log.warning("Rate limit on delete — waiting 60s...")
            time.sleep(60)
            return self.delete_message(message_id)  # retry once
        except Exception as e:
            log.error(f"Delete failed for message {message_id}: {e}")
            return False


# =============================================================================
# DM DELETER
# =============================================================================

class DMDeleter:
    """
    Main orchestrator for DM conversation deletion.

    Workflow:
        1. Authenticate via OAuth 1.0a
        2. Fetch all DM conversations via API
        3. Apply optional filters
        4. Delete all messages in each target conversation
        5. Write forensic logs
    """

    def __init__(self, config: Config):
        self.config          = config
        self.api             = XApiClient(config)
        self.logger          = None
        self.filters_active  = {}

    def _confirm(self, description: str) -> bool:
        """Prompt user for explicit confirmation before destructive action."""
        print(f"\n{'=' * 70}")
        print(f"⚠  WARNING: About to delete DM conversations — {description}")
        print(f"⚠  This action is PERMANENT and IRREVERSIBLE")
        print(f"⚠  Messages are deleted from YOUR view only (X platform limitation)")

        if self.filters_active:
            print("\n   Active filters:")
            for name, desc in self.filters_active.items():
                print(f"   - {name}: {desc}")

        print(f"{'=' * 70}\n")
        return input("Type 'DELETE ALL' to confirm: ") == "DELETE ALL"

    def run(
        self,
        dry_run           : bool       = True,
        limit             : int | None = None,
        participant_ids   : list       = None,
    ):
        """
        Execute DM deletion session.

        Args:
            dry_run         : If True, log only — do not delete anything
            limit           : Max conversations to process (None = all)
            participant_ids : Only delete conversations involving these user IDs
        """

        # Initialize forensic logger
        if self.config.log_deletions:
            self.logger = ForensicLogger(self.config.log_dir)

        # Track active filters for logging/display
        if participant_ids:
            self.filters_active["Participants"] = ", ".join(participant_ids)
            if self.logger:
                self.logger.manifest_data["filters_applied"].append(
                    f"participant_ids: {participant_ids}"
                )
        if limit:
            self.filters_active["Limit"] = str(limit)

        # Authenticate
        if not self.api.connect():
            return

        # Fetch conversations
        conversations = self.api.get_dm_conversations()
        if not conversations:
            print("No conversations found or unable to retrieve. Exiting.")
            return

        # Apply limit
        target = conversations[:limit] if limit else conversations
        mode   = "DRY RUN MODE" if dry_run else "🔥 DELETION MODE 🔥"
        print(f"\n{mode} — {len(target)} conversation(s) to process\n")

        # Confirm before real deletion
        if not dry_run:
            desc = f"{len(target)} conversation(s)"
            if not self._confirm(desc):
                print("\nAborted.")
                return

        conv_deleted  = 0
        conv_skipped  = 0
        msg_deleted   = 0
        errors        = 0

        for i, conv in enumerate(target, 1):
            cid      = conv["id"]
            msgs     = conv["messages"]
            p_ids    = conv.get("participant_ids", [])

            # Apply participant filter
            if participant_ids and not ConversationFilters.by_participant(p_ids, participant_ids):
                conv_skipped += 1
                print(f"  ⤷ FILTERED  [{i}] conv={cid} (participant not in filter list)")
                if self.logger:
                    for m in msgs:
                        self.logger.log_message(
                            cid, m["id"], m["sender_id"], m["created_at"],
                            m["text"], "FILTERED", "Participant not in filter list"
                        )
                continue

            print(f"  Processing [{i}/{len(target)}] conv={cid}  ({len(msgs)} messages)")

            conv_success = True
            for msg in msgs:
                mid  = msg["id"]
                text = msg["text"]
                ts   = msg["created_at"]
                sid  = msg["sender_id"]

                if dry_run:
                    preview = text[:60] + "..." if len(text) > 60 else text
                    print(f"    [DRY RUN] Would delete msg={mid}: {preview}")
                    if self.logger:
                        self.logger.log_message(
                            cid, mid, sid, ts, text,
                            "DRY_RUN_DELETE", "Would be deleted"
                        )
                    msg_deleted += 1
                else:
                    ok = self.api.delete_message(mid)
                    if ok:
                        msg_deleted += 1
                        print(f"    ✓ Deleted msg={mid}")
                        if self.logger:
                            self.logger.log_message(
                                cid, mid, sid, ts, text,
                                "DELETED", "Successfully deleted"
                            )
                    else:
                        errors     += 1
                        conv_success = False
                        print(f"    ✗ Failed  msg={mid}")
                        if self.logger:
                            self.logger.log_message(
                                cid, mid, sid, ts, text,
                                "ERROR", "Deletion failed"
                            )

                    time.sleep(self.config.delay)

            if conv_success:
                conv_deleted += 1
            print()

        # Finalize
        if self.logger:
            self.logger.update_manifest("conversations_processed", len(target))
            self.logger.update_manifest("messages_deleted",        msg_deleted)
            self.logger.update_manifest("conversations_skipped",   conv_skipped)
            self.logger.update_manifest("errors",                  errors)
            self.logger.finalize()

        print(f"{'=' * 70}")
        print("SUMMARY")
        print(f"{'=' * 70}")
        print(f"Conversations processed : {len(target)}")
        print(f"Conversations completed : {conv_deleted}")
        print(f"Conversations skipped   : {conv_skipped}")
        print(f"Messages deleted        : {msg_deleted}")
        print(f"Errors                  : {errors}")
        print(f"{'=' * 70}")


# =============================================================================
# COMMAND LINE INTERFACE
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Twitter/X DM Conversation Deletion Tool — API Version (OAuth 1.0a)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
NOTES:
  - DM listing requires X API Basic tier ($100/mo) or higher
  - Authentication uses 4 API keys — no username/password stored
  - X deletes messages from YOUR view only; recipient's copy is unaffected
  - Get your keys: https://developer.twitter.com/en/portal/dashboard
    App permissions required: Read + Write + Direct Messages

EXAMPLES:
  # Safe dry run (default) — shows what would be deleted
  python3 dm_deleter_selenium.py

  # Delete all conversations
  python3 dm_deleter_selenium.py --execute

  # Delete first 10 conversations only
  python3 dm_deleter_selenium.py --execute --limit 10

  # Delete conversations with specific user IDs only
  python3 dm_deleter_selenium.py --execute --participant-ids 123456789 987654321

  # Custom config file
  python3 dm_deleter_selenium.py --execute --config my_config.json
        """
    )

    parser.add_argument(
        "--config", default="config_dm.json",
        help="Path to config file (default: config_dm.json)"
    )
    parser.add_argument(
        "--execute", action="store_true",
        help="Actually delete conversations. Dry run by default."
    )
    parser.add_argument(
        "--limit", type=int, metavar="N",
        help="Max number of conversations to process"
    )
    parser.add_argument(
        "--participant-ids", nargs="+", metavar="USER_ID",
        help="Only delete conversations with these X user IDs"
    )
    parser.add_argument(
        "--no-log", action="store_true",
        help="Disable forensic logging"
    )

    args = parser.parse_args()

    print("=" * 70)
    print("Twitter/X DM Conversation Deletion Tool — API Version v2.0.0")
    print("=" * 70)
    print("Auth: OAuth 1.0a (API keys) — no username/password required")
    print("=" * 70)

    config = Config(args.config)

    if args.no_log:
        config.log_deletions = False

    dry_run = not args.execute or config.dry_run

    if dry_run:
        print("\n⚠  DRY RUN MODE — nothing will be deleted")
        print("   Use --execute to perform actual deletion\n")

    DMDeleter(config).run(
        dry_run         = dry_run,
        limit           = args.limit,
        participant_ids = args.participant_ids,
    )


if __name__ == "__main__":
    main()
