# SPDX-License-Identifier: Apache-2.0
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools" / "kvio"))

from agent_trace import (  # noqa: E402
    TraceError,
    compile_lmcache_agent,
    compile_tracelab,
    normalize_timestamp,
    read_records,
    validate_plan,
)


def source_record(text, timestamp, line, session="source-session"):
    return {
        "input": text, "timestamp": timestamp, "session_id": session,
        "_kvio_file": "/trace/task.jsonl", "_kvio_line": line,
        "_kvio_ingest": line - 1,
    }


def simple_encode(text):
    return [ord(character) for character in text]


class AgentTraceTest(unittest.TestCase):
    def test_normalizes_seconds_milliseconds_and_microseconds(self):
        expected = 1_765_000_000.0
        self.assertEqual(normalize_timestamp(expected, "test"), expected)
        self.assertEqual(normalize_timestamp(expected * 1_000, "test"), expected)
        self.assertEqual(normalize_timestamp(expected * 1_000_000, "test"), expected)

    def test_content_prefix_plan_derives_reuse_without_random_hit_rate(self):
        records = [
            source_record("abcd", 1_765_000_000, 1),
            source_record("abcdef", 1_765_000_001_000, 2),
        ]
        plan = compile_lmcache_agent(
            records, [], encode=simple_encode,
            tokenizer={"name": "test", "revision": "local"}, chunk_tokens=2,
        )
        validate_plan(plan)
        self.assertEqual(plan["summary"]["stores"], 3)
        self.assertEqual(plan["summary"]["loads"], 2)
        self.assertEqual(plan["summary"]["duration_s"], 1)
        self.assertEqual(
            [op["op"] for op in plan["requests"][1]["operations"]],
            ["load", "load", "store"])

    def test_substring_policy_finds_shifted_complete_chunks(self):
        records = [
            source_record("abcd", 1_765_000_000, 1),
            source_record("xxabcd", 1_765_000_001, 2),
        ]
        plan = compile_lmcache_agent(
            records, [], encode=simple_encode,
            tokenizer={"name": "test", "revision": "local"}, chunk_tokens=2,
            policy="substring",
        )
        self.assertEqual(plan["summary"]["loads"], 2)
        self.assertEqual(plan["summary"]["stores"], 3)

    def test_tracelab_uses_observed_prefix_and_warms_unknown_history(self):
        records = []
        for index, (total, prefix) in enumerate(((1024, 512), (1280, 1024))):
            records.append({
                "provider": "claude", "project": "p", "session_id": "s",
                "round_index": index, "input_tokens_total": total,
                "prefix_tokens": prefix,
                "timing_events": [{"timestamp": f"2026-06-01T00:00:0{index}Z"}],
                "_kvio_file": "/trace/tracelab.jsonl", "_kvio_line": index + 1,
                "_kvio_ingest": index,
            })
        plan = compile_tracelab(records, [], chunk_tokens=256)
        validate_plan(plan)
        self.assertEqual(plan["summary"]["warm_chunks"], 2)
        self.assertEqual(plan["summary"]["loads"], 6)
        self.assertEqual(plan["summary"]["stores"], 3)

    def test_strict_jsonl_rejects_a_malformed_record(self):
        with tempfile.TemporaryDirectory() as directory:
            trace = Path(directory) / "trace.jsonl"
            trace.write_text('{"input":"ok"}\n{broken}\n', encoding="utf-8")
            with self.assertRaisesRegex(TraceError, "invalid JSON"):
                read_records(str(trace))

    def test_strict_jsonl_records_artifact_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            trace = Path(directory) / "trace.jsonl"
            trace.write_text(json.dumps({"input": "ok"}) + "\n", encoding="utf-8")
            records, files = read_records(str(trace))
            self.assertEqual(len(records), 1)
            self.assertEqual(len(files[0]["sha256"]), 64)


if __name__ == "__main__":
    unittest.main()
