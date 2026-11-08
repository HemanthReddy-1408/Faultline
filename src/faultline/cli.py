import argparse
import json
import sys
from pathlib import Path


def main(argv=None):
    ap = argparse.ArgumentParser(prog="faultline")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("investigate", help="investigate a bundle JSON file or a generated demo scenario")
    s.add_argument("bundle", nargs="?", help="path to a bundle JSON; omit with --demo")
    s.add_argument("--demo", action="store_true")
    s.add_argument("--cause", default="pool_exhaustion")
    s.add_argument("--variant", default="rich", choices=["rich", "plain", "bare"])
    s.add_argument("--split", default="held", choices=["dev", "held"])
    s.add_argument("--json", action="store_true")
    e = sub.add_parser("eval", help="run the full benchmark")
    e.add_argument("--reranker", action="append", default=[], help="label=path-or-hf-id of an extra reranker, e.g. rankforge=../RankForge/artifacts/model")
    sv = sub.add_parser("serve")
    sv.add_argument("--port", type=int, default=8200)
    sv.add_argument("--host", default="127.0.0.1")
    a = ap.parse_args(argv)
    if a.cmd == "investigate":
        from .graph import investigate
        from .kb import default_kb
        from .report import to_markdown
        from .schema import Bundle
        from .synth import make_scenario

        raw = make_scenario(7, a.split, variant=a.variant, cause_id=a.cause)["bundle"] if a.demo or not a.bundle else json.loads(Path(a.bundle).read_text())
        rep = investigate(Bundle(**raw), default_kb())
        print(rep.model_dump_json(indent=1) if a.json else to_markdown(rep))
    elif a.cmd == "eval":
        from .eval import ROOT, run_all

        extra = dict(x.split("=", 1) for x in a.reranker)
        r = run_all(ROOT / "results", extra, log=lambda *x: print(*x, file=sys.stderr))
        print((ROOT / "results" / "RESULTS.md").read_text())
    else:
        import uvicorn

        uvicorn.run("faultline.api:create_app", factory=True, host=a.host, port=a.port)


if __name__ == "__main__":
    main()
