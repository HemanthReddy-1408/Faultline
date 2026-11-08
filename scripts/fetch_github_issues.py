"""Fetch real public GitHub issues about CI/infra failure modes (unauthenticated Search API, rate-limited).

Output: data/github_issues.jsonl — title, truncated body, URL, repo, labels. Excerpts are kept short and always carry
their source URL; the text belongs to the original authors. Real data, as opposed to the labelled-synthetic CI scenarios.
"""
import json, sys, time
from pathlib import Path
import httpx

REPOS = ["sqlalchemy/sqlalchemy", "psycopg/psycopg2", "redis/redis-py", "urllib3/urllib3", "brettwooldridge/HikariCP",
         "aio-libs/aiohttp", "encode/httpx", "pgbouncer/pgbouncer", "docker/compose", "pytest-dev/pytest", "grpc/grpc",
         "pypa/pip", "alembic/alembic"]
TERMS = ["connection timeout", "pool exhausted", "connection reset", "connection refused", "out of memory", "no space left",
         "certificate expired", "name resolution", "rate limit 429", "flaky test", "migration failed", "dependency conflict"]
out = Path(__file__).resolve().parents[1] / "data" / "github_issues.jsonl"
seen, rows = set(), []
with httpx.Client(timeout=30, headers={"Accept": "application/vnd.github+json", "User-Agent": "faultline-dataset-builder"}) as c:
    for i, term in enumerate(TERMS):
        repos = " ".join(f"repo:{r}" for r in REPOS)
        r = c.get("https://api.github.com/search/issues", params={"q": f'{term} is:issue {repos}', "per_page": 30, "sort": "reactions"})
        if r.status_code != 200:
            print("skip", term, r.status_code, r.text[:100]); time.sleep(10); continue
        for it in r.json().get("items", []):
            if it["html_url"] in seen or not it.get("body"):
                continue
            seen.add(it["html_url"])
            rows.append({"id": "gh:" + it["repository_url"].split("repos/")[1] + "#" + str(it["number"]), "repo": it["repository_url"].split("repos/")[1],
                         "number": it["number"], "title": it["title"], "body": it["body"][:1200], "url": it["html_url"],
                         "labels": [l["name"] for l in it["labels"]], "state": it["state"], "source": "github-real"})
        print(term, len(rows)); time.sleep(7)
out.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
print("wrote", len(rows), "issues ->", out)
