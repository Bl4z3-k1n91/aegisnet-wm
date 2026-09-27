from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import numpy as np


COMMON = (
    "x",
    "future_state",
    "future_label",
    "attack",
    "change",
    "onset",
    "infiltration",
    "victim",
    "current_label",
    "campaign_id",
)


def load_split(path: Path, split: str) -> dict[str, np.ndarray]:
    with np.load(path / f"{split}.npz", allow_pickle=False) as data:
        return {name: data[name] for name in COMMON}


def repeated(arrays: dict[str, np.ndarray], count: int, prefix: str) -> dict[str, np.ndarray]:
    result: dict[str, np.ndarray] = {}
    for name, values in arrays.items():
        if name == "campaign_id":
            copies = []
            for index in range(count):
                copies.append(np.asarray([f"{prefix}-r{index}-{value}" for value in values], dtype="U128"))
            result[name] = np.concatenate(copies, axis=0)
        else:
            result[name] = np.concatenate([values] * count, axis=0)
    return result


def prefixed(arrays: dict[str, np.ndarray], prefix: str) -> dict[str, np.ndarray]:
    result = dict(arrays)
    result["campaign_id"] = np.asarray(
        [f"{prefix}-{value}" for value in arrays["campaign_id"]],
        dtype="U128",
    )
    return result


def concat(parts: list[dict[str, np.ndarray]]) -> dict[str, np.ndarray]:
    return {name: np.concatenate([part[name] for part in parts], axis=0) for name in COMMON}


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a real public + local EVE hybrid temporal release.")
    parser.add_argument("--public-dir", type=Path, required=True)
    parser.add_argument("--local-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--local-train-repeat", type=int, default=50)
    parser.add_argument("--local-val-repeat", type=int, default=25)
    args = parser.parse_args()
    public_manifest = json.loads((args.public_dir / "manifest.json").read_text(encoding="utf-8"))
    local_manifest = json.loads((args.local_dir / "manifest.json").read_text(encoding="utf-8"))
    if list(public_manifest["features"]) != list(local_manifest["features"]):
        raise RuntimeError("public/local feature schemas differ")
    for key in ("history_steps", "window_seconds", "horizons_steps"):
        if public_manifest.get(key) != local_manifest.get(key):
            raise RuntimeError(f"public/local {key} differs")

    public_train = prefixed(load_split(args.public_dir, "train"), "genis-train")
    public_val = prefixed(load_split(args.public_dir, "val"), "genis-val")
    local_train = repeated(load_split(args.local_dir, "train"), args.local_train_repeat, "eve-train")
    local_val = repeated(load_split(args.local_dir, "val"), args.local_val_repeat, "eve-val")
    local_test = prefixed(load_split(args.local_dir, "test"), "eve-test")

    train = concat([public_train, local_train])
    val = concat([public_val, local_val])
    test = local_test

    args.output_dir.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(args.output_dir / "train.npz", **train)
    np.savez_compressed(args.output_dir / "val.npz", **val)
    np.savez_compressed(args.output_dir / "test.npz", **test)
    manifest = {
        "release": args.output_dir.name,
        "evidence_status": "real_hybrid_dataset",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "features": list(public_manifest["features"]),
        "feature_count": int(public_manifest["feature_count"]),
        "history_steps": int(public_manifest["history_steps"]),
        "window_seconds": int(public_manifest["window_seconds"]),
        "horizons_steps": list(public_manifest["horizons_steps"]),
        "horizons_seconds": list(public_manifest["horizons_seconds"]),
        "sources": {
            "public": public_manifest.get("release", args.public_dir.name),
            "local": local_manifest.get("release", args.local_dir.name),
        },
        "split_strategy": (
            "training/validation combine disjoint GeNIS scenarios with repeated EVE train/val runs; "
            "test is untouched EVE test runs only"
        ),
        "local_train_repeat": args.local_train_repeat,
        "local_val_repeat": args.local_val_repeat,
        "victim_supervision": "generic only: mixed public/local assets are not used for production victim supervision",
        "warning": (
            "EVE local sample count remains small; repetition changes training weight but does not create new independent evidence"
        ),
        "splits": {
            "train": {"sequences": int(len(train["x"]))},
            "val": {"sequences": int(len(val["x"]))},
            "test": {"sequences": int(len(test["x"])), "source": "untouched local EVE test only"},
        },
    }
    (args.output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
