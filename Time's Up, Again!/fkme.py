import subprocess

# pycompile fkme.py

isLoop = True
while isLoop:
    proc = subprocess.Popen(
        "./main", stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    question = proc.stdout.readline()[10:-1]

    answer = str(eval(question))
    proc.stdin.write(answer+'\n')

    for _ in range(10):
        data = proc.stdout.readline()
        if 'pico' in data:
            print(data)
            isLoop = False
