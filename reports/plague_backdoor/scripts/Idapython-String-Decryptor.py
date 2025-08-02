import binascii
from unicorn import *
from unicorn.x86_const import *
import ida_segment
import ida_bytes
import ida_funcs
import ida_nalt
import idc
import idautils

class Runner:
    # Constants for the emulated stack
    STACK_ADDR = 0x0FF00000
    STACK_SIZE = 0x10000

    def __init__(self):
        # Initialize Unicorn in 64-bit x86 mode
        self.mu = Uc(UC_ARCH_X86, UC_MODE_64)
        self.hook_list = {}

        # Determine the range of memory to map based on IDA segments
        self.low_addr = min(ida_segment.getnseg(i).start_ea for i in range(ida_segment.get_segm_qty()))
        self.length = max(self.align(ida_segment.getnseg(i).end_ea - self.low_addr) for i in range(ida_segment.get_segm_qty()))
        
        # Map binary memory and stack into Unicorn
        self.mu.mem_map(self.low_addr, self.length)
        print("Mapped binary memory:", hex(self.low_addr), "size:", hex(self.length))
        self.mu.mem_map(self.STACK_ADDR, self.STACK_SIZE)

        # Copy IDA's segment bytes into Unicorn memory
        for i in range(ida_segment.get_segm_qty()):
            seg = ida_segment.getnseg(i)
            data = ida_bytes.get_bytes(seg.start_ea, seg.end_ea - seg.start_ea)
            if data:
                self.mu.mem_write(seg.start_ea, data)

        # Load imported function thunks to hook
        for addr, name in self.get_imports():
            self.hook_list[addr] = name

    @staticmethod
    def align(size, alignment=0x1000):
        # Align size to nearest page boundary
        return (size + alignment - 1) & ~(alignment - 1)

    def exec_func(self, func_name: str | int) -> int:
        # Resolve function address from name or address
        if isinstance(func_name, str):
            func = ida_funcs.get_func(idc.get_name_ea_simple(func_name))
        else:
            func = ida_funcs.get_func(func_name)

        start_offset = func.start_ea

        # Set up the stack with a fake return address (0x0)
        rsp = self.STACK_ADDR + self.STACK_SIZE // 2 - 8
        self.mu.mem_write(rsp, (0).to_bytes(8, 'little'))  # push 0
        self.mu.reg_write(UC_X86_REG_RSP, rsp)

        # Install instruction hook
        self.mu.hook_add(UC_HOOK_CODE, self._hook_code, self)

        # Start emulation from the function start
        self.mu.emu_start(start_offset, 0)

        # Return value from RAX
        return self.mu.reg_read(UC_X86_REG_RAX)

    def _hook_external_call(self, name):
        print(f"[HOOK] External function: {name}")

        if name.startswith("memcpy"):
            dest = self.mu.reg_read(UC_X86_REG_RDI)
            src = self.mu.reg_read(UC_X86_REG_RSI)
            n = self.mu.reg_read(UC_X86_REG_RDX)
            self.mu.mem_write(dest, bytes(self.mu.mem_read(src, n)))

        elif name.startswith("strlen"):
            rdi = self.mu.reg_read(UC_X86_REG_RDI)
            rax = 0
            while self.mu.mem_read(rdi + rax, 1)[0] != 0:
                rax += 1
            self.mu.reg_write(UC_X86_REG_RAX, rax)

        else:
            print(f"[!] Unknown external call: {name}")
            self.mu.emu_stop()
            return

        # Simulate `ret` after external call (pop RIP)
        rsp = self.mu.reg_read(UC_X86_REG_RSP)
        ret_addr = int.from_bytes(self.mu.mem_read(rsp, 8), 'little')
        self.mu.reg_write(UC_X86_REG_RSP, rsp + 8)
        self.mu.reg_write(UC_X86_REG_RIP, ret_addr)
        print(f"Returning to 0x{ret_addr:X}")

    @staticmethod
    def _hook_code(uc, address, size, self):
        # Stop execution if return address is 0
        if address == 0:
            print("[*] Reached return address 0 — stopping emulation")
            self.mu.emu_stop()
            return

        # Call external hook if the address matches an import
        if address in self.hook_list:
            self._hook_external_call(self.hook_list[address])

    @staticmethod
    def get_imports():
        # Flatten all imported symbols into a list of (address, name)
        result = []
        for i in range(ida_nalt.get_import_module_qty()):
            def _cb(ea, name, ordinal):
                result.append((ea, name or f"ord_{ordinal}"))
                return True
            ida_nalt.enum_import_names(i, _cb)
        return result

    def get_string_at(self, addr):
        # Read a null-terminated string from memory
        i = 0
        while self.mu.mem_read(addr + i, 1)[0] != 0:
            i += 1
        return self.mu.mem_read(addr, i).decode()

    def dump(self, filename="/dev/shm/dump.bin"):
        with open(filename, "wb") as fd:
            fd.write(bytes(self.mu.mem_read(self.low_addr, self.length)))

my_runner = Runner()

# Run initialization function
my_runner.exec_func("init_phrases")

# Get the target address for the decrypt function
target = list(idautils.CodeRefsTo(idc.get_name_ea_simple("decrypt_phrase"), 0))[0]

# Feel free to dump to use with `strings`
my_runner.dump()

print("Decrypting strings...", hex(target))

for ref in idautils.CodeRefsTo(target, 0):
    print("Found ref:", hex(target))
    prev = ref
    offset = idc.BADADDR

    # Look backward up to 5 instructions to find `mov edi, imm`
    for _ in range(5):
        if (idc.print_insn_mnem(prev) == "mov" and
            idc.print_operand(prev, 0) == "edi" and
            idc.get_operand_type(prev, 1) == idc.o_imm):
            offset = idc.get_operand_value(prev, 1)
            break
        prev = idc.prev_head(prev)

    if offset == idc.BADADDR:
        print(f"[!] Could not find argument for call at {hex(ref)}")
        continue

    # Set EDI for decryption and run function
    my_runner.mu.reg_write(UC_X86_REG_EDI, offset)
    print(f"[+] Calling decrypt_phrase({offset}) at 0x{ref:X}")
    result_addr = my_runner.exec_func(target)

    # Read decrypted string
    decrypted = my_runner.get_string_at(result_addr)
    idc.set_cmt(ref, decrypted, 0)
    print(f"[*] Commented: '{decrypted}' at 0x{ref:X}")
