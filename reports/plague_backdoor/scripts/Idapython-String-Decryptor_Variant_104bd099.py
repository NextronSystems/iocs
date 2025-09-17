import idautils
import idc
import ida_name
import struct
import array

decrypted_cache_ptr = ida_name.get_name_ea(idaapi.BADADDR, "decrypted_cache_ptr")
phrases = ida_name.get_name_ea(idaapi.BADADDR, "phrases")
__s_b_ptr = ida_name.get_name_ea(idaapi.BADADDR, "__s_b")
__s_ptr = ida_name.get_name_ea(idaapi.BADADDR, "__s") + 0x10

assert decrypted_cache_ptr != idaapi.BADADDR
assert phrases != idaapi.BADADDR
assert __s_b_ptr != idaapi.BADADDR
assert __s_ptr != idaapi.BADADDR

__s_b = ida_bytes.get_bytes(__s_b_ptr, 1024)
__s = ida_bytes.get_bytes(__s_ptr, 0x20)


def decrypt(offset):
    """Deobfuscate string using sboxes"""
    if decrypted_cache_ptr + offset * 8 == 0:
        return  # should never happen
    # Each encrypted script is described in a struct
    enc_str_ptr, enc_str_len = struct.unpack("<QQ", ida_bytes.get_bytes(phrases + offset * 0x10, 16))
    enc_str = ida_bytes.get_bytes(enc_str_ptr, enc_str_len)

    retval = b""
    for i in range(enc_str_len):
        # Diffuser
        V2 = __s[(i & 0xF) & (0xf + 0x10)] & 0x7
        var_32 = 0xff & (enc_str[i] << (8 - V2)) | (enc_str[i] >> V2)
        var_33 = 0xff & (i + __s[i & 0xf])
        # SBOX
        a = __s_b[var_33 ^ var_32]
        retval += bytes((a,))
    return retval.decode()


# crawl throw the dc_p callbacks
for callback in idautils.XrefsTo(ida_name.get_name_ea(idaapi.BADADDR, ".dc_p")):
    prev = idc.prev_head(callback.frm)
    assert prev != idaapi.BADADDR
    assert idc.get_operand_type(prev, 0) == idc.o_reg and idc.get_operand_type(prev, 1) == idc.o_imm
    curr_string = decrypt(idc.get_operand_value(prev, 1))
    print(f'Found string {hex(prev)} "{curr_string}"')
    idc.set_cmt(callback.frm, f'ENC_STR: "{curr_string}"', 0)

