import requests
from url_safety import normalize_url, safe_get, UnsafeURLError


def verify_url(url):

    try:
        url = normalize_url(url)
    except UnsafeURLError as exc:
        return {"status": "Invalid URL", "code": None, "risk": "Unknown", "detail": str(exc)}

    result = {
        "status": "Unknown",
        "code": None,
        "risk": "Unknown"
    }

    try:

        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 "
                "(KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            )
        }

        response = safe_get(
            requests,
            url,
            headers=headers,
            timeout=10,
            max_redirects=5,
        )

        code = response.status_code

        result["code"] = code

        # --------------------------------------------------
        # Successful website
        # --------------------------------------------------

        if 200 <= code < 300:

            result["status"] = "Active"
            result["risk"] = "Low"

        # --------------------------------------------------
        # Redirect
        # --------------------------------------------------

        elif 300 <= code < 400:

            result["status"] = "Active / Redirect"
            result["risk"] = "Low"

        # --------------------------------------------------
        # Access denied
        # --------------------------------------------------

        elif code == 403:

            result["status"] = "Active / Access Denied"
            result["risk"] = "Medium"

        # --------------------------------------------------
        # Authentication required
        # --------------------------------------------------

        elif code == 401:

            result["status"] = "Active / Authentication Required"
            result["risk"] = "Medium"

        # --------------------------------------------------
        # Not found
        # --------------------------------------------------

        elif code == 404:

            result["status"] = "Not Found"
            result["risk"] = "Medium"

        # --------------------------------------------------
        # Server errors
        # --------------------------------------------------

        elif 500 <= code < 600:

            result["status"] = "Server Error"
            result["risk"] = "Medium"

        # --------------------------------------------------
        # Other responses
        # --------------------------------------------------

        else:

            result["status"] = f"HTTP {code}"
            result["risk"] = "Medium"

    except requests.exceptions.Timeout:

        result["status"] = "Connection Timeout"
        result["risk"] = "Medium"

    except requests.exceptions.ConnectionError:

        result["status"] = "Connection Failed"
        result["risk"] = "High"

    except requests.exceptions.RequestException:

        result["status"] = "Request Failed"
        result["risk"] = "Medium"

    except UnsafeURLError as exc:
        result["status"] = "Blocked for safety"
        result["detail"] = str(exc)
        result["risk"] = "Unknown"

    except Exception:

        result["status"] = "Unknown"
        result["risk"] = "Medium"

    return result
