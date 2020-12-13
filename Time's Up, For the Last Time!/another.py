import subprocess

# pycompile fkme.py


proc = subprocess.Popen(
    "./main", stdin=subprocess.PIPE, stdout=subprocess.PIPE)
proc.stdin.write('0')
proc.stdin.write('0')

for _ in range(10):
    data = proc.stdout.readline()
    print(data)

