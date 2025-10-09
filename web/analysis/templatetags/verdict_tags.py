from django import template

register = template.Library()

_RED = {"malware", "grayware", "phishing", "c2"}
_MAP = {
    "benign":  "alert alert-success",
    "error":   "alert alert-warning",
    "pending": "alert alert-info",   # light blue
}

def _normalize(val):
    # Accept either a dict (with 'verdict_text' or 'verdict') or a plain string
    if isinstance(val, dict):
        val = val.get("verdict_text") or val.get("verdict") or ""
    return (val or "").strip().lower()

@register.filter
def verdict_alert_class(value, default="alert alert-secondary"):
    """
    Return Bootstrap alert classes for a verdict.
    Examples:
      benign   -> alert alert-success
      malware  -> alert alert-danger
      error    -> alert alert-warning
      pending  -> alert alert-info
      (other)  -> alert alert-secondary
    """
    v = _normalize(value)
    if v in _RED:
        return "alert alert-danger"
    return _MAP.get(v, default)
