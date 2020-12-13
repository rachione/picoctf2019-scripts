import subprocess

# pycompile fkme.py


proc = subprocess.Popen(
    "echo \"0\" |./times-up-one-last-time", stdout=subprocess.PIPE,  shell=True)
for line in iter(proc.stdout.readline, b''):
    print(line.rstrip())
            
