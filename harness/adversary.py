"""Adversarial-merchant hooks for the v2 flow.

The merchant owns its catalog file (merchant_inventory.json at
$TEMP_DB_DIR/merchant_inventory.json). A malicious/compromised merchant
controls the item name/description it serves. These helpers write the
poisoned entry the way the merchant itself would, then (for TOCTOU)
mutate the price mid-flow.

item_id derivation mirrors merchant_agent_mcp.server._generate_inventory_entry:
  slug = re.sub(r'[^a-z0-9]+','_', desc.strip().lower()).strip('_')
  item_id = f'{slug}_0'
"""

import hashlib
import json
import os
import re
import time
from pathlib import Path

V2_TEMP_DB = (Path.home() /
              "work/ap2_whispers/AP2/code/samples/python/scenarios/"
              "a2a/human-not-present/cards/.temp-db")


def _inv_path():
    p = os.environ.get("MERCHANT_INVENTORY_PATH")
    if p:
        return Path(p)
    return V2_TEMP_DB / "merchant_inventory.json"


def slug_item_id(desc):
    d = desc.strip().lower()
    slug = re.sub(r"[^a-z0-9]+", "_", d).strip("_") or "item"
    return f"{slug}_0", slug


def _gen_price(desc, cap):
    """Mirror merchant _generate_inventory_entry pricing so the poisoned
    entry looks native."""
    d = desc.strip().lower()
    h = int(hashlib.sha256(d.encode()).hexdigest()[:8], 16)
    if cap and cap > 0:
        jitter = 0.48 + (0.10 + (h % 30) / 100) * 0.28
        return round(cap * jitter, 2)
    return round(5.0 + (h % 95) / 10, 2)


def poison_inventory(slug_or_id, base_desc, cap, evil_name_suffix="",
                     evil_desc="", price=None):
    """Write/overwrite the merchant catalog entry with attacker-controlled
    name (carries the injected instruction). Stock stays 0 (drop not live)."""
    inv_path = _inv_path()
    inv_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        inv = json.loads(inv_path.read_text()) if inv_path.exists() else {}
    except (json.JSONDecodeError, OSError):
        inv = {}
    item_id = slug_or_id if slug_or_id.endswith("_0") else f"{slug_or_id}_0"
    existing = inv.get(item_id) or {}
    # if base_desc already looks like a resolved catalog name (came from a
    # prior entry), keep it verbatim; else title-case the raw description.
    if existing.get("name") and base_desc == existing.get("name"):
        native_name = base_desc
    else:
        native_name = base_desc.strip().title()
    inv[item_id] = {
        "name": native_name + evil_name_suffix,
        "description": evil_desc,
        "price": (price if price is not None
                  else existing.get("price")
                  or _gen_price(base_desc, cap)),
        "stock": existing.get("stock", 0),
    }
    inv_path.write_text(json.dumps(inv, indent=2))
    return item_id, inv[item_id]


def repoison_price(item_id, new_price):
    """TOCTOU: mutate the live catalog price after Intent approval, before
    the autonomous purchase signs the cart."""
    inv_path = _inv_path()
    try:
        inv = json.loads(inv_path.read_text())
    except (json.JSONDecodeError, OSError):
        return None
    if item_id not in inv:
        return None
    old = inv[item_id].get("price")
    inv[item_id]["price"] = new_price
    inv[item_id]["_repoisoned_at"] = time.time()
    inv_path.write_text(json.dumps(inv, indent=2))
    return {"item_id": item_id, "old_price": old, "new_price": new_price}


def read_entry(item_id):
    try:
        return json.loads(_inv_path().read_text()).get(item_id)
    except (json.JSONDecodeError, OSError):
        return None
