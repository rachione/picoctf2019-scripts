import subprocess


proc = subprocess.Popen("./times-up", stdin=subprocess.PIPE, stdout=subprocess.PIPE)
question = proc.stdout.readline()
print(question)
ans = question.split(b":")[1]
ans = str(eval(ans))

out, _ = proc.communicate(input = ans.encode('utf-8'))
print(out)




