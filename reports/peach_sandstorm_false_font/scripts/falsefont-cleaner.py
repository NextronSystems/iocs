import os
import sys
import clr
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# https://github.com/0xd4d/dnlib
dnlib_dll_path = os.path.join(os.path.dirname(__file__), "dnlib")
clr.AddReference(dnlib_dll_path)

import dnlib
from dnlib.DotNet import ModuleDefMD, DummyLogger, MDToken
from dnlib.DotNet.Emit import OpCodes, OperandType
from dnlib.DotNet.Writer import ModuleWriterOptions


class Cleaner:
    def __init__(self, file_path) -> None:
        self.file_path: str = file_path
        self.moduleDef: ModuleDefMD = ModuleDefMD.Load(file_path)

        # These might be binary specific so you will need to change them depending on the sample
        self.method_name: str = "Core.Agent.Utilities.Constants::D(System.String)"
        self.aes_key: str = "3EzuNZ0RN3h3oV7rzILktSHSaHk+5rtcWOr0mlA1CUA="
        self.aes_iv: str = "viOIZ9cX59qDDjMHYsz1Yw=="

        self.strings_to_inline = []

    # Get top level and nested types
    def get_all_types(self):
        top_level_types = [t for t in self.moduleDef.Types]
        nested_types = [
            nested_type for t in self.moduleDef.Types for nested_type in t.NestedTypes
        ]
        return top_level_types + nested_types

    def get_operand(self, inst):
        if inst.OpCode == OpCodes.Ldstr:
            return inst.Operand
        else:
            return None
    
    def get_string(self, key):
        for item in self.strings_to_inline:
            if item[0] == key:
                return item[1]

    def aes_decrypt(self, encrypted_string, base64_key, base64_iv):
        key = base64.b64decode(base64_key)
        iv = base64.b64decode(base64_iv)
        encrypted_data = base64.b64decode(encrypted_string)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
        decrypted_text = decrypted_data.decode("utf-8")
        return decrypted_text

    def decrypt_strings(self):
        for typeDef in self.get_all_types():
            if not typeDef.HasMethods:
                continue

            for method in typeDef.Methods:
                if not method.HasBody:
                    continue

                for index, inst in enumerate(method.Body.Instructions):
                    if inst.OpCode != OpCodes.Call:
                        continue

                    if self.method_name not in str(inst.Operand):
                        continue

                    if (method.Body.Instructions[index - 1].OpCode != OpCodes.Ldstr):
                        continue
                    

                    operand = self.get_operand(method.Body.Instructions[index - 1])
                    if operand is not None:
                        try:
                            result = self.aes_decrypt(
                                operand, self.aes_key, self.aes_iv)
                            print(result)
                        except Exception as e:
                            continue

                        if not result:
                            continue

                        if (len(method.Body.Instructions) == 3):
                            self.strings_to_inline.append((method.FullName, result))

                         # Nop string argument
                        method.Body.Instructions[index - 1].OpCode = OpCodes.Nop
                         # Replace call with decrypted string
                        method.Body.Instructions[index].OpCode = OpCodes.Ldstr
                        method.Body.Instructions[index].Operand = result
    
    def inline_strings(self):
        method_names = [item[0] for item in self.strings_to_inline]
        for typeDef in self.get_all_types():
            if not typeDef.HasMethods:
                continue

            for method in typeDef.Methods:
                if not method.HasBody:
                    continue

                for index, inst in enumerate(method.Body.Instructions):
                    if inst.OpCode != OpCodes.Call:
                        continue
                    
                    if (str(inst.Operand) not in method_names):
                        continue
                    
                    result = self.get_string(str(inst.Operand))
                    inst.OpCode = OpCodes.Ldstr
                    inst.Operand = result


    def save_module(self):
        options = ModuleWriterOptions(self.moduleDef)
        options.Logger = DummyLogger.NoThrowInstance

        split_name = self.file_path.rsplit(".", 1)
        output_path = (
            f"{split_name[0]}_cleaned.{split_name[1]}"
            if len(split_name) > 1
            else f"{split_name[0]}_cleaned"
        )

        self.moduleDef.Write(output_path, options)


def main():
    if len(sys.argv) < 2:
        sys.exit("falsefont-cleaner.py <target_file>")

    file_path = sys.argv[1]

    if not os.path.exists(file_path):
        sys.exit(f"[ERROR]: Could not find file {file_path}")

    if not os.path.isabs(file_path):
        file_path = os.path.abspath(file_path)

    cleaner = Cleaner(file_path)

    cleaner.decrypt_strings()
    cleaner.inline_strings()
    cleaner.save_module()


if __name__ == "__main__":
    main()