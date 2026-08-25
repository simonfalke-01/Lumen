#!/usr/bin/env python3
"""Independent evaluator for the checked-in START/mode boundary vectors."""

from __future__ import annotations

import json
import math
from pathlib import Path


FIXTURE = Path(__file__).with_name("start_mode_vectors.json")


def load_fixture() -> dict:
    """Load the language-neutral contract and vectors."""
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def admit(vector: dict, contract: dict) -> str:
    """Return the stable admission result for one vector."""
    width = vector["width"]
    height = vector["height"]
    numerator = vector["refresh_numerator"]
    denominator = vector["refresh_denominator"]
    if not (
        contract["minimum_width"] <= width <= contract["maximum_width"]
        and contract["minimum_height"] <= height <= contract["maximum_height"]
        and width % 2 == 0
        and height % 2 == 0
    ):
        return "dimensions"
    if not (
        0 < numerator <= contract["maximum_rational_component"]
        and 0 < denominator <= contract["maximum_rational_component"]
    ):
        return "refresh_component"
    if math.gcd(numerator, denominator) != 1:
        return "refresh_unreduced"
    if not (
        numerator >= contract["minimum_refresh_hz"] * denominator
        and numerator <= contract["maximum_refresh_hz"] * denominator
    ):
        return "refresh_range"
    if vector["codec"] not in contract["codec"].values():
        return "codec"
    valid_color_mode = vector["chroma"] in contract["chroma"].values() and (
        vector["dynamic_range"] == contract["dynamic_range"]["sdr"]
        and vector["bit_depth"] == 8
        or vector["dynamic_range"]
        in (contract["dynamic_range"]["pq"], contract["dynamic_range"]["hlg"])
        and vector["bit_depth"] == 10
    )
    if not valid_color_mode:
        return "color_mode"
    if vector["codec"] == contract["codec"]["h264"] and (
        width > contract["h264_maximum_dimension"]
        or height > contract["h264_maximum_dimension"]
        or vector["dynamic_range"] != contract["dynamic_range"]["sdr"]
        or vector["bit_depth"] != 8
    ):
        return "h264_limit"
    if not 1 <= vector["fidelity"] <= 3 or (
        vector["fidelity"] == contract["fidelity"]["codec_lossless"]
        and (
            vector["chroma"] != contract["chroma"]["yuv444"]
            or vector["codec_flags"] & contract["codec_lossless_proof_flag"] == 0
        )
    ):
        return "fidelity"
    return "none"


def main() -> int:
    """Validate every checked-in vector and print one result per ID."""
    fixture = load_fixture()
    failures = 0
    for vector in fixture["vectors"]:
        actual = admit(vector, fixture["contract"])
        print(f"{vector['id']}: {actual}")
        failures += actual != vector["expected"]
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
