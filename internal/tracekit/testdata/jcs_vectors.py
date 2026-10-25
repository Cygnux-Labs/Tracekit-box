import json, rfc8785
from tracekit.format.canon import event_hash, loads_strict
vectors = [
 r'{"tool":"Bash","args":{"command":"ls"}}',
 r'{"tool":"Bash","args":{"command":"ls -la /workspace"}}',
 r'{"tool":"WebFetch","args":{"url":"https://pypi.org:443"}}',
 r'{"€":1,"\r":2,"1":3,"😀":4,"דּ":5,"a":6}',
 r'{"😀":1,"😁":2,"￿":3,"":4,"é":5,"e":6}',
 r'"\u0000\u0001\u001f\u007f\b\f\n\r\t\"\\/"',
 r'"  <>&é中😀"',
 r'{"b":[1,2,{"z":null,"y":true,"x":false}],"a":{"c":"d"},"":"","e":[],"f":{}}',
 r'[0,-0,1.0,1e21,1.5e-7,1e-6,1e-7,0.1,100.0,1e300,5e-324,1.7976931348623157e308,9007199254740991,-9007199254740991,123.456,0.30000000000000004,1234567890123456789e-5,-1.5,2.5e-10,1e20,123456789012345680000.0]',
 r'{"text":"line1\nline2\ttab \u0007bell","emoji 🎉":"🎉","nested":{"deep":[[[["x"]]]]}}',
]
out = []
for v in vectors:
    x = loads_strict(v)
    out.append({"in": v, "canon": rfc8785.dumps(x).decode("utf-8"), "hash": event_hash(x)})
print(json.dumps(out, ensure_ascii=True, indent=1))
