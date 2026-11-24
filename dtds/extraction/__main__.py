import argparse
import json

from dtds.extraction import extract_file


def main():
    ap = argparse.ArgumentParser(description="Extract IOCs from threat-report files")
    ap.add_argument("files", nargs="+")
    ap.add_argument("--include-private", action="store_true",
                    help="keep private/reserved IP addresses (normally dropped)")
    args = ap.parse_args()
    out = {f: extract_file(f, args.include_private).to_dict() for f in args.files}
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
