"""
AEGIS — Keyword Matching Baseline (TF-IDF)

Control implementation for the ablation test.
Simple TF-IDF cosine similarity over raw log fields.
Used as the "keyword matching" baseline that BGE-m3 should outperform.

Ref: Methodology §5.4 — Ablation Testing: Semantic Embedding vs. Keyword Matching
"""

from __future__ import annotations

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


class KeywordBaseline:
    """
    TF-IDF + cosine similarity keyword matching baseline.

    This is the "control" against which BGE-m3 semantic embedding
    is compared in the ablation test.
    """

    def __init__(self):
        self.vectorizer = TfidfVectorizer(
            max_features=5000,
            stop_words="english",
            ngram_range=(1, 2),
        )
        self._corpus: list[str] = []
        self._fitted = False

    def fit(self, corpus: list[str]) -> None:
        """Fit the TF-IDF model on a corpus of texts."""
        self._corpus = corpus
        self.vectorizer.fit(corpus)
        self._fitted = True

    def query(self, query_text: str, top_k: int = 10) -> list[tuple[int, float]]:
        """
        Find the top-k most similar documents to the query.

        Returns:
            List of (document_index, similarity_score) tuples
        """
        if not self._fitted or not self._corpus:
            return []

        # Transform corpus and query
        corpus_vectors = self.vectorizer.transform(self._corpus)
        query_vector = self.vectorizer.transform([query_text])

        # Compute cosine similarity
        similarities = cosine_similarity(query_vector, corpus_vectors).flatten()

        # Get top-k indices
        top_indices = np.argsort(similarities)[::-1][:top_k]

        return [(int(idx), float(similarities[idx])) for idx in top_indices]

    def batch_query(
        self, queries: list[str], corpus: list[str], top_k: int = 10
    ) -> list[list[tuple[int, float]]]:
        """
        Query multiple texts against a corpus.

        Returns:
            List of result lists, one per query
        """
        self.fit(corpus)
        results = []
        for q in queries:
            results.append(self.query(q, top_k=top_k))
        return results
