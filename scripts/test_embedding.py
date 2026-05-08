import urllib.request
import json

def test_embedding():
    url = "http://localhost:8001/embed"
    data = {"text": "test embedding"}
    req = urllib.request.Request(url, data=json.dumps(data).encode(), headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req) as response:
            res = json.loads(response.read().decode())
            print(f"[OK] Embedding dimension: {len(res['embedding'])}")
            print(f"[OK] First 5 values: {res['embedding'][:5]}")
            return True
    except Exception as e:
        print(f"[FAIL] Embedding test failed: {e}")
        return False

if __name__ == "__main__":
    test_embedding()
