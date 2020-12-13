stringBuilder1 = 'aaa'
stringBuilder2 = 'aaa'
stringBuilder3 = 'aaa'
stringBuilder4 = 'aaa'

stringBuilder1 = list(stringBuilder1)
stringBuilder2 = list(stringBuilder2)
stringBuilder3 = list(stringBuilder3)
stringBuilder4 = list(stringBuilder4)

stringBuilder1[0] = chr(ord(stringBuilder1[0])+4)
stringBuilder1[1] = chr(ord(stringBuilder1[1])+19)
stringBuilder1[2] = chr(ord(stringBuilder1[2])+18)

stringBuilder2[0] = chr(ord(stringBuilder2[0])+7)
stringBuilder2[1] = chr(ord(stringBuilder2[1])+0)
stringBuilder2[2] = chr(ord(stringBuilder2[2])+1)

stringBuilder3[0] = chr(ord(stringBuilder3[0])+0)
stringBuilder3[1] = chr(ord(stringBuilder3[1])+11)
stringBuilder3[2] = chr(ord(stringBuilder3[2])+15)

stringBuilder4[0] = chr(ord(stringBuilder4[0])+14)
stringBuilder4[1] = chr(ord(stringBuilder4[1])+20)
stringBuilder4[2] = chr(ord(stringBuilder4[2])+15)


print(''.join(stringBuilder3)+''.join(stringBuilder2) +
      ''.join(stringBuilder1)+''.join(stringBuilder4))


#alphabetsoup