from time import sleep
import subprocess

# Find the open screen session
session = subprocess.run(["screen", "-ls"], stdout=subprocess.PIPE).stdout.split()[5]
print(f"Using session {session.decode()}")
# Dump 64 kb at a time
for i in range(0, 0x1000000, 0x10000):
    subprocess.run(["screen", "-S", session, "-p", "0", "-X", "stuff", f"spi read {i:x} 10000\\n"])
    # 40 seconds is enough to print all the data
    sleep(40)
    print(f"Done {i//0x10000}")