import sys
import os
import unittest.mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from core.advanced_protection import advanced_protection, ThreatLevel

def test_ssti_detection():
    print("Running SSTI tests...")
    payloads = [
        "{{ 7 * 7 }}",
        "${7 * 7}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "${T(java.lang.Runtime).getRuntime().exec('id')}",
    ]
    for p in payloads:
        detections = advanced_protection.analyze(
            path="/",
            query=p,
            body="",
            headers={},
            client_ip="127.0.0.1",
            ml_score=0.0
        )
        assert any(d.category in ["SSTI", "SSTI_SUSPICIOUS"] for d in detections), f"Failed to detect SSTI: {p}"
    print("SSTI tests passed!")

def test_request_smuggling_detection():
    print("Running Request Smuggling tests...")
    headers1 = {"Content-Length": "0", "Transfer-Encoding": "chunked"}
    detections1 = advanced_protection.analyze("/", "", "", headers1, "127.0.0.1")
    assert any(d.category == "HTTP_SMUGGLING_CL_TE" for d in detections1), "Failed to detect CL.TE"

    headers2 = {"transfer-encoding ": "chunked"}
    detections2 = advanced_protection.analyze("/", "", "", headers2, "127.0.0.1")
    assert any(d.category == "HTTP_SMUGGLING_OBFUSCATED" for d in detections2), "Failed to detect Obfuscated TE"

    body_smuggle = "0\r\n\r\nPOST /admin HTTP/1.1\r\nHost: internal\r\n\r\n"
    detections3 = advanced_protection.analyze("/", "", body_smuggle, {}, "127.0.0.1")
    assert any(d.category == "HTTP_SMUGGLING_BODY" for d in detections3), "Failed to detect body smuggling"
    print("Request Smuggling tests passed!")

def test_deserialization_detection():
    print("Running Deserialization tests...")
    payloads = [
        "O:8:\"stdClass\":0:{}",
        "c__builtin__\neval",
        "_$$ND_FUNC$$_console.log()"
    ]
    for p in payloads:
        detections = advanced_protection.analyze("/", p, "", {}, "127.0.0.1")
        assert any(d.category == "DESERIALIZATION" for d in detections), f"Failed to detect Deserialization: {p}"

    # Java magic bytes test
    detections = advanced_protection.analyze("/", "", "", {}, "127.0.0.1", file_content=b'\xac\xed\x00\x05sr\x00')
    assert any(d.category == "DESERIALIZATION_JAVA" for d in detections), "Failed to detect Java Deserialization"
    print("Deserialization tests passed!")

def test_advanced_ssrf_detection():
    print("Running Advanced SSRF tests...")
    payloads = [
        "http://2130706433/",
        "http://0x7f000001/",
        "http://0177.0.0.01/",
        "dict://127.0.0.1:11211/stat",
        "http://latest/meta-data/"
    ]
    for p in payloads:
        detections = advanced_protection.analyze("/", p, "", {}, "127.0.0.1")
        assert any(d.category == "SSRF_ADVANCED" for d in detections), f"Failed to detect Advanced SSRF: {p}"
    print("Advanced SSRF tests passed!")

if __name__ == "__main__":
    try:
        test_ssti_detection()
        test_request_smuggling_detection()
        test_deserialization_detection()
        test_advanced_ssrf_detection()
        print("ALL SECURITY TESTS PASSED")
    except AssertionError as e:
        print(f"TEST FAILED: {e}")
        sys.exit(1)
