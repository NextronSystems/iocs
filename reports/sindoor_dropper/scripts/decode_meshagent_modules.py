import zlib
import magic
import tempfile
import re
import base64
import pathlib
import sys

try:
   data = pathlib.Path(sys.argv[1]).read_bytes()
except IndexError:
   print("Usage: python decrypt_mesh_modules.py <path_to_encrypted_file>")
   sys.exit(1)


def decode_module_data(encoded_str: str) -> str:
   data = base64.b64decode(encoded_str)
   while magic.from_buffer(data) == "zlib compressed data":
      data = zlib.decompress(data)
   return data.decode()

with tempfile.TemporaryDirectory() as _tempdir:

   #for module in re.findall(rb"addCompressedModule.*?'(.*?').*Buffer.from\('(.*?)'\)", data):
   for module_name, module_data in re.findall(rb"addCompressedModule.*?'(.*?').*?'(.*?')", data):
      module_name = module_name.decode()
      print("Decoding module:", module_name)
      module_data = decode_module_data(module_data.decode())

      pathlib.Path(_tempdir, module_name + '.js').write_text(module_data)
   input(f"Data saved to {_tempdir}. Press a key to delete...")