import tarfile
import time


output=""
i = 720
while i > 0:
    with tarfile.open("%d.tar" % i) as tar:
        tar.extractall()
    time.sleep(0.5)
    with open("filler.txt") as f:
        data = f.read()
        output+=data
        print(data)
    i -= 1

with open("output.txt",'w') as f:
    f.write(output)