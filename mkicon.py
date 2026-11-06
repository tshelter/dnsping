# Generates a tiny PNG-compressed 32x32 .ico: blue rounded square with a white pulse line.
import struct, zlib, math
S = 32
def inside_round(x, y, r=6):
    cx = min(max(x, r), S - 1 - r); cy = min(max(y, r), S - 1 - r)
    return (x - cx) ** 2 + (y - cy) ** 2 <= r * r
pts = [(4,17),(10,17),(13,9),(17,24),(20,13),(22,17),(28,17)]
def dist_seg(px, py, a, b):
    (x1,y1),(x2,y2) = a, b
    dx, dy = x2-x1, y2-y1
    t = max(0, min(1, ((px-x1)*dx + (py-y1)*dy) / (dx*dx+dy*dy)))
    return math.hypot(px-(x1+t*dx), py-(y1+t*dy))
rows = b''
for y in range(S):
    row = b'\0'
    for x in range(S):
        if not inside_round(x, y):
            row += b'\0\0\0\0'; continue
        d = min(dist_seg(x+.5, y+.5, pts[i], pts[i+1]) for i in range(len(pts)-1))
        a = max(0.0, min(1.0, 2.2 - d))
        base = (0x1e, 0x6f, 0xd9)
        c = tuple(int(b + (255-b)*a) for b in base)
        row += bytes(c) + b'\xff'
    rows += row
def chunk(t, d): return struct.pack('>I', len(d)) + t + d + struct.pack('>I', zlib.crc32(t+d) & 0xffffffff)
png = b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', S, S, 8, 6, 0, 0, 0)) + chunk(b'IDAT', zlib.compress(rows, 9)) + chunk(b'IEND', b'')
ico = struct.pack('<HHH', 0, 1, 1) + struct.pack('<BBBBHHII', S, S, 0, 0, 1, 32, len(png), 22) + png
open('app.ico', 'wb').write(ico)
print(len(ico), 'bytes')
