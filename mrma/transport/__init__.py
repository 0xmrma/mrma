"""Transport adapters. Semantic HTTP is normalized and is not wire-exact."""

from .semantic_http import SemanticHttpAdapter, TransportPolicyError

__all__ = ["SemanticHttpAdapter", "TransportPolicyError"]
