"""In-memory Elasticsearch stand-in for offline worker tests (no network, no ES)."""

from __future__ import annotations

from fnmatch import fnmatch, fnmatchcase
from functools import cmp_to_key
import json
from typing import Any
from urllib.parse import unquote, urlsplit

from soc.workers.https import DeliveryError


def dig(document: dict, dotted: str) -> Any:
    value: Any = document
    for part in dotted.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def matches(document: dict, query: dict) -> bool:
    if not query or "match_all" in query:
        return True
    if "bool" in query:
        clause = query["bool"]
        for item in clause.get("filter", []) + clause.get("must", []):
            if not matches(document, item):
                return False
        for item in clause.get("must_not", []):
            if matches(document, item):
                return False
        should = clause.get("should", [])
        if should and not any(matches(document, item) for item in should):
            return False
        return True
    if "range" in query:
        (field, bounds), = query["range"].items()
        value = dig(document, field)
        if value is None:
            return False
        for operator, bound in bounds.items():
            if operator == "gte" and not value >= bound:
                return False
            if operator == "gt" and not value > bound:
                return False
            if operator == "lte" and not value <= bound:
                return False
            if operator == "lt" and not value < bound:
                return False
        return True
    if "terms" in query:
        (field, values), = query["terms"].items()
        value = dig(document, field)
        candidates = value if isinstance(value, list) else [value]
        return any(item in values for item in candidates)
    if "term" in query:
        (field, expected), = query["term"].items()
        if isinstance(expected, dict):
            expected = expected["value"]
        value = dig(document, field)
        candidates = value if isinstance(value, list) else [value]
        return expected in candidates
    if "exists" in query:
        return dig(document, query["exists"]["field"]) is not None
    if "wildcard" in query:
        (field, spec), = query["wildcard"].items()
        pattern = spec["value"] if isinstance(spec, dict) else spec
        value = dig(document, field)
        return isinstance(value, str) and fnmatchcase(value, pattern)
    if "match_phrase" in query:
        (field, phrase), = query["match_phrase"].items()
        value = dig(document, field)
        return isinstance(value, str) and str(phrase) in value
    raise NotImplementedError(f"fake Elasticsearch does not support query {query!r}")


class FakeElastic:
    """Duck-types ``soc.workers.https.JsonHTTPS`` for the subset the workers use."""

    def __init__(self) -> None:
        self.documents: dict[tuple[str, str], dict] = {}
        self.requests: list[tuple[str, str]] = []
        self.fail_create: Exception | None = None

    def add(self, index: str, doc_id: str, document: dict) -> None:
        self.documents[(index, doc_id)] = json.loads(json.dumps(document))

    def indices(self, pattern: str) -> list[str]:
        patterns = pattern.split(",")
        return sorted({index for index, _ in self.documents if any(fnmatch(index, item) for item in patterns)})

    def docs_in(self, pattern: str) -> list[dict]:
        names = set(self.indices(pattern))
        return [doc for (index, _), doc in self.documents.items() if index in names]

    def request(self, method: str, path: str, payload: dict | None = None):
        self.requests.append((method, path))
        parsed = urlsplit(path)
        parts = [unquote(part) for part in parsed.path.strip("/").split("/")]
        if method == "PUT" and len(parts) == 3 and parts[1] == "_create":
            if self.fail_create is not None:
                raise self.fail_create
            index, _, doc_id = parts
            if (index, doc_id) in self.documents:
                raise DeliveryError("HTTP_409", retryable=False, status=409)
            self.documents[(index, doc_id)] = json.loads(json.dumps(payload))
            return 201, {"result": "created"}
        if method == "POST" and len(parts) == 2 and parts[1] == "_search":
            return 200, {"hits": {"hits": self._search(parts[0], payload or {})}}
        raise NotImplementedError((method, path))

    def _search(self, pattern: str, body: dict) -> list[dict]:
        names = set(self.indices(pattern))
        rows = [
            (index, doc_id, doc)
            for (index, doc_id), doc in self.documents.items()
            if index in names and matches(doc, body.get("query", {}))
        ]
        sort_spec = body.get("sort") or [{"@timestamp": "asc"}]

        def key_of(row):
            index, doc_id, doc = row
            values = []
            for item in sort_spec:
                (field, order), = item.items()
                order = order["order"] if isinstance(order, dict) else order
                values.append((doc_id if field == "_id" else dig(doc, field), order))
            return values

        def compare(left, right):
            for (lv, order), (rv, _) in zip(key_of(left), key_of(right)):
                if lv == rv:
                    continue
                result = -1 if (lv is None or (rv is not None and lv < rv)) else 1
                return result if order == "asc" else -result
            return 0

        rows.sort(key=cmp_to_key(compare))
        after = body.get("search_after")
        if after is not None:
            def after_row(row):
                return [value for value, _ in key_of(row)]

            kept = []
            for row in rows:
                values = after_row(row)
                ordering = [order for _, order in key_of(row)]
                decided = False
                greater = False
                for current, bound, order in zip(values, after, ordering):
                    if current == bound:
                        continue
                    ahead = current > bound
                    greater = ahead if order == "asc" else not ahead
                    decided = True
                    break
                if decided and greater:
                    kept.append(row)
            rows = kept
        hits = []
        for index, doc_id, doc in rows[: body.get("size", 10)]:
            source = doc
            fields = body.get("_source")
            if fields is not None:
                source = {}
                for dotted in fields:
                    value = dig(doc, dotted)
                    if value is None:
                        continue
                    node = source
                    *parents, leaf = dotted.split(".")
                    for part in parents:
                        node = node.setdefault(part, {})
                    node[leaf] = value
            hits.append({
                "_index": index, "_id": doc_id, "_source": source,
                "sort": [value for value, _ in key_of((index, doc_id, doc))],
            })
        return hits
