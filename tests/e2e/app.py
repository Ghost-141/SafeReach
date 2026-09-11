"""Sits there logging, with secrets in its environment and argv, like a real service."""

import os
import sys
import time

while True:
    print(
        f"app tick port={sys.argv[-1]} env=STRIPE_KEY is set: {bool(os.environ.get('STRIPE_KEY'))}",
        flush=True,
    )
    time.sleep(5)
