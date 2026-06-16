import time

def allocate_chunk(buf, size_mb):
    buf.append(bytearray(size_mb * 1024 * 1024))

def keep_allocating(buf):
    while True:
        allocate_chunk(buf, 10)

def spin(seconds):
    end = time.time() + seconds
    while time.time() < end:
        pass

def main():
    spin(15)
    buf = []
    keep_allocating(buf)

main()
