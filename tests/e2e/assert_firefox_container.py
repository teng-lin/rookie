#!/usr/bin/env python3
"""Assert one browser-produced Firefox container cookie through Python."""

from __future__ import annotations

import argparse
import sys

import rookie_cookies


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("database")
    parser.add_argument("user_context_id", type=int)
    parser.add_argument(
        "origin_attributes",
        help="the verbatim originAttributes suffix Firefox wrote for this row",
    )
    args = parser.parse_args()
    snapshot = rookie_cookies.from_path(args.database)
    context = {
        "url": "https://container.rookie.test/",
        "top_level_site": "https://container.rookie.test/",
        "user_context_id": args.user_context_id,
    }
    if snapshot.header(context) != "rookie_container=container-1":
        raise RuntimeError("Python did not select the exact Firefox container cookie")
    if snapshot.header({**context, "user_context_id": args.user_context_id + 1}) != "":
        raise RuntimeError("Python merged a different Firefox container")

    view = snapshot.send_view(context)
    identities = [
        (record["cookie"]["name"], record["cookie"]["value"])
        for record in view["cookies"]
    ]
    if identities != [("rookie_container", "container-1")]:
        raise RuntimeError(f"Python send_view selected {identities!r}")
    if view["header"] != "rookie_container=container-1":
        raise RuntimeError(f"Python send_view header was {view['header']!r}")
    # The raw suffix is never a bypass: the typed container selector still has
    # to match, so naming the stored suffix must land on the same single record
    # rather than widening the set.
    round_trip = snapshot.send_view(
        {**context, "origin_attributes": args.origin_attributes}
    )
    if round_trip["cookies"] != view["cookies"]:
        raise RuntimeError(
            f"the raw origin-attribute selector {args.origin_attributes!r} changed "
            f"the selected set: {round_trip['cookies']!r}"
        )

    try:
        snapshot.header(
            {
                "url": context["url"],
                "top_level_site": context["top_level_site"],
            }
        )
    except Exception as error:
        if getattr(error, "code", None) != "incomplete_send_context" and (
            "incomplete_send_context" not in str(error)
        ):
            raise
        required = list(getattr(error, "required", None) or [])
        if required != ["user_context_id"]:
            raise RuntimeError(
                f"Python named the wrong required selectors: {required!r}"
            ) from error
    else:
        raise RuntimeError("Python accepted a missing Firefox container selector")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"Firefox container Python assertion failed: {error}", file=sys.stderr)
        raise
