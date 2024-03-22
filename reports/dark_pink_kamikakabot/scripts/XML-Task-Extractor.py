import sys

def read_file_until_null_byte(file_path):

    chunk_size = 1024  # Adjust this based on your needs
    with open(file_path, 'rb') as file:
        file.seek(0, 2)  # Move to the end of the file
        file_size = file.tell()
        data = []
        
        while file.tell() > 0:
            current_position = max(file.tell() - chunk_size, 0)  # Calculate position to start reading
            file.seek(current_position)
            chunk = file.read(min(chunk_size, file_size - current_position))
            null_byte_position = chunk.rfind(b'\x00')  # Find null byte in the current chunk
            
            if null_byte_position != -1:
                # Found the null byte, read until this point and break
                data.append(chunk[null_byte_position+1:])
                break
            else:
                # No null byte, keep this chunk and continue
                data.append(chunk)
                file.seek(current_position)  # Move back to read the next chunk
            
            if file.tell() == 0:
                # If we're at the start of the file, ensure we break the loop
                break

        data.reverse()  # Reverse the order of chunks (we read the file backwards)
        result = b''.join(data)
        return result

def main():
    # Check if the correct number of arguments are provided
    if len(sys.argv) != 3:
        # python3 XML-Task-Extractor.py "~CN AOIP-based Comprehensive Regional Architecture.doc" afc4b8a1d3f2e1b3
        print("Usage: python XML-Task-Extractor.py [Malicious_DOC] [XOR_KEY]")
        exit()

    # file_path = '~CN AOIP-based Comprehensive Regional Architecture.doc'
    # xor_key = bytes.fromhex("afc4b8a1d3f2e1b3")

    file_path = read_file_until_null_byte(sys.argv[1])
    xor_key = bytes.fromhex(sys.argv[2])

    xml_content = ""
    for i in range(len(file_path)):
        xml_content += chr(file_path[i] ^ xor_key[i%len(xor_key)])

    with open("build.xml", "w") as f:
        print(xml_content[0:10000])
        f.write(xml_content)

if __name__ == "__main__":
    main()
