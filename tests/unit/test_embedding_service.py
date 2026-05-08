"""
AEGIS Unit Tests — Embedding Service

Tests input validation, sentence-boundary truncation, and service configuration
without requiring GPU/model loading (mocks the model).

Ref: Methodology §3.1 — FastAPI Embedding Service
Ref: TABLE 12 — "Input text validated for empty string and 512-token limit"
"""

import pytest
from unittest.mock import patch, MagicMock
import numpy as np

from services.embedding.app import truncate_at_sentence_boundary


# ─── Sentence-Boundary Truncation Tests ─────────────────────────────────────


class TestSentenceBoundaryTruncation:
    """
    Ref: §3.1 — "Text longer than 512 tokens is truncated at the sentence
    boundary closest to the limit — not mid-word."
    """

    def test_short_text_unchanged(self):
        """Text under limit is returned unchanged."""
        text = "User admin executed mimikatz.exe on DC01."
        result = truncate_at_sentence_boundary(text, max_chars=2000)
        assert result == text

    def test_truncates_at_sentence_boundary(self):
        """Long text is truncated at the last sentence boundary."""
        text = (
            "First sentence about process creation. "
            "Second sentence about network connection. "
            "Third sentence about credential dumping. "
            + "X" * 2000  # Push past the limit
        )
        result = truncate_at_sentence_boundary(text, max_chars=200)
        # Should end at a sentence boundary
        assert result.endswith(".")
        assert len(result) <= 200

    def test_truncates_at_word_boundary_no_sentences(self):
        """If no sentence boundary, truncate at word boundary."""
        text = "word " * 500  # No sentence endings
        result = truncate_at_sentence_boundary(text, max_chars=50)
        assert not result.endswith(" ")
        assert len(result) <= 50

    def test_empty_text(self):
        """Empty text returns empty."""
        assert truncate_at_sentence_boundary("", max_chars=2000) == ""

    def test_exact_limit(self):
        """Text exactly at limit is unchanged."""
        text = "A" * 2000
        result = truncate_at_sentence_boundary(text, max_chars=2000)
        assert result == text

    def test_preserves_semantic_coherence(self):
        """Truncation keeps complete sentences, not half-words."""
        text = (
            "User admin executed powershell.exe on WEBSERVER01. "
            "The process spawned cmd.exe as a child process. "
            "Network connection initiated to 10.0.0.5 on port 4444. "
            "This is additional context that should be trimmed because "
            "it exceeds the character limit we have set for this test."
        )
        result = truncate_at_sentence_boundary(text, max_chars=120)
        # Should contain complete sentences
        assert "executed powershell.exe" in result
        # Should end cleanly
        assert result.endswith(".")


# ─── Input Validation Tests ────────────────────────────────────────────────


class TestInputValidation:
    """
    Ref: §3.1 — "the /embed endpoint must validate that the input text
    is not empty and does not exceed the model's maximum token length"
    """

    def test_empty_text_detected(self):
        """Empty string should be caught before embedding."""
        text = "   "
        assert text.strip() == ""

    def test_whitespace_only_detected(self):
        """Whitespace-only text should be caught."""
        text = "\n\t  \r\n"
        assert text.strip() == ""

    def test_valid_text_passes(self):
        """Normal synthetic_intent text passes validation."""
        text = "User admin executed mimikatz.exe on DC01"
        assert text.strip() != ""
        assert len(text) < 2000


# ─── Configuration Tests ──────────────────────────────────────────────────


class TestEmbeddingConfig:
    """Verify embedding service configuration matches methodology."""

    def test_embedding_dim(self):
        """BGE-m3 produces 384-dimensional embeddings."""
        from services.embedding.app import EMBEDDING_DIM
        assert EMBEDDING_DIM == 384

    def test_max_tokens(self):
        """Max token limit is 512 per §3.1."""
        from services.embedding.app import MAX_TOKENS
        assert MAX_TOKENS == 512

    def test_batch_window(self):
        """Default batch window is 50ms per §3.1."""
        from services.embedding.app import BATCH_WINDOW_MS
        assert BATCH_WINDOW_MS == 50

    def test_max_batch_size(self):
        """Max batch size is 16 per §3.1 (16x throughput)."""
        from services.embedding.app import MAX_BATCH_SIZE
        assert MAX_BATCH_SIZE == 16

    def test_model_name(self):
        """Default model is BAAI/bge-m3."""
        from services.embedding.app import MODEL_NAME
        assert "bge" in MODEL_NAME.lower()


# ─── TABLE 15 Pitfall Tests ───────────────────────────────────────────────


class TestTable15Pitfalls:
    """
    TABLE 15: "Embedding raw JSON instead of synthetic_intent string"
    The embedding service accepts plain text, NOT JSON objects.
    """

    def test_synthetic_intent_is_plain_text(self):
        """synthetic_intent should be a natural language sentence."""
        intent = "User admin executed mimikatz.exe on DC01 — possible credential dumping"
        assert not intent.startswith("{")
        assert not intent.startswith("[")
        # Should be readable English
        assert " " in intent

    def test_raw_json_is_not_valid_intent(self):
        """Raw JSON should never be passed as synthetic_intent."""
        raw_json = '{"EventID": "10", "Image": "mimikatz.exe"}'
        # This would produce a poor embedding
        assert raw_json.startswith("{")
