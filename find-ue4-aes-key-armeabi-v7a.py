# find-ue4-aes-key-armeabi-v7a.py
# By GHFear @ IllusorySoftware

import ida_search
import ida_bytes
import idautils
import ida_segment
import ida_kernwin
import idc
import struct
import binascii

KEY_SIZE = 32  # AES-256 = 32 bytes

def read_u32(ea):
    b = ida_bytes.get_bytes(ea, 4)
    if not b or len(b) < 4:
        return None
    return struct.unpack("<I", b)[0]

def read_key(ea, n=KEY_SIZE):
    b = ida_bytes.get_bytes(ea, n)
    if not b or len(b) < n:
        return None
    return b

def find_pattern_in_segment(start_ea, end_ea, pattern):
    matches = []
    ea = ida_search.find_binary(start_ea, end_ea, pattern, 16, ida_search.SEARCH_DOWN)
    while ea != idc.BADADDR:
        matches.append(ea)
        next_start = ea + 1
        if next_start >= end_ea:
            break
        ea = ida_search.find_binary(next_start, end_ea, pattern, 16, ida_search.SEARCH_DOWN)
    return matches

def scan_all_segments(pattern):
    results = {}
    for seg_start in idautils.Segments():
        seg = ida_segment.getseg(seg_start)
        if seg is None:
            continue
        start = seg.start_ea
        end = seg.end_ea
        if end - start < 1:
            continue
        matches = find_pattern_in_segment(start, end, pattern)
        if matches:
            results[start] = matches
    return results

def ask_pattern():
    default = "00 48 2D E9 ? ? ? ? 0C 10 9F E5 20 20 A0 E3 ? ? ? ? 25 D8 B5 EB 00 88 BD E8"
    res = ida_kernwin.ask_str(default, 0, "Enter binary pattern (hex bytes, use ? as wildcard)")
    if not res:
        raise SystemExit("No pattern provided.")
    return " ".join(res.strip().split())

def extract_ldr_key(match_ea, ldr_offset_in_pattern):
    """Extract AES key from ARM32 function pattern, accounting for +8 PC offset"""
    ldr_ea = match_ea + ldr_offset_in_pattern
    instr = read_u32(ldr_ea)
    if instr is None:
        print("  [!] Cannot read LDR instruction at 0x{:08X}".format(ldr_ea))
        return

    # Decode LDR literal address
    imm12 = instr & 0xFFF
    pc = (ldr_ea & ~3) + 8
    literal_va = pc + imm12

    val = read_u32(literal_va)
    if val is None:
        print("  [!] Cannot read value at literal 0x{:08X}".format(literal_va))
        return

    # Compute base key address
    key_va = (val + pc + 8) & 0xFFFFFFFF  # <<<<<< add +8 to reach real key

    key_bytes = read_key(key_va, KEY_SIZE)
    if key_bytes is None:
        print("  [!] Cannot read 32 bytes at key VA 0x{:08X}".format(key_va))
        return

    print("Match 0x{:08X}: Key VA 0x{:08X}  =>  0x{}".format(
        match_ea, key_va, binascii.hexlify(key_bytes).decode()
    ))

def main(pattern=None, ldr_offset_in_pattern=8):
    if pattern is None:
        pattern = ask_pattern()

    print("[*] Scanning segments for pattern '{}'".format(pattern))
    results = scan_all_segments(pattern)
    if not results:
        print("[-] No matches found.")
        return

    for seg_start, addrs in results.items():
        for ea in addrs:
            extract_ldr_key(ea, ldr_offset_in_pattern)

if __name__ == "__main__":
    main()
