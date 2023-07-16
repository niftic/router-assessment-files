with open("flash.txt", "r") as dumpfile, open("flash.bin", "wb") as binfile:
    curr = -1
    for line in dumpfile:
        line = line.rstrip("\n")
        # Sanity check that we didn't miss any chunk
        if line.startswith("MT7621 # spi read") or line.startswith("spi read"):
            print(line)
            index = int(line.split()[-2], 16)//0x10000
            print(f"Parsing index {index}")
            if index != curr + 1:
                print(f"[!] Invalid index: {index}")
                exit(1)
            curr = index
        # Filter out the lines containing garbage
        elif len(line) == 0 or any(map(line.startswith, ["read len", "Unknown command", "MT7621 #"])):
            continue
        # Write out content to binary file
        else:
            values = line.split()
            if len(values) != 65536:
                print(f"[!] Invalid number of bytes: {len(values)}")
                exit(1)
            binfile.write(bytes(map(lambda x: int(x, 16), values)))
            if curr == 255:
                break