import ctypes
import time

def spin(seconds):
    end = time.time() + seconds
    while time.time() < end:
        pass

def allocate_chunk(lib, size_mb):
    lib.allocate_megabytes(size_mb)

def keep_allocating(lib):
    while True:
        allocate_chunk(lib, 10)

def main():
    lib = ctypes.CDLL('/libvictim_c.so')
    spin(10)
    keep_allocating(lib)

main()
