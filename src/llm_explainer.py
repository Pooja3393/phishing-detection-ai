"""
Compatibility wrapper forwarding to ai_explainer.
"""
from ai_explainer import explain_url, explain_qr, explain_visual

__all__ = ["explain_url", "explain_qr", "explain_visual"]
