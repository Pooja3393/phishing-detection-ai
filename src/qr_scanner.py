"""
Compatibility wrapper forwarding to qr_scan and qr_detector.
"""
from qr_detector import decode_qr
from qr_scan import scan_qr

__all__ = ["decode_qr", "scan_qr"]
