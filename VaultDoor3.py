encpwd = "jU5t_a_sna_3lpm12gb44_u_4_m1r240"

buffer = [0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 15, 9, 14, 10, 13, 11, 12, 12, 11, 13, 10, 14, 9, 15, 8, 16,
          30, 18, 28, 20, 26, 22, 24, 24, 22, 26, 20, 28, 18, 30, 16, 31, 31, 29, 29, 27, 27, 25, 25, 23, 23, 21, 21, 19, 19, 17, 17]

ans = [0]*32

for i,k in list(zip(buffer[0::2], buffer[1::2]))[::-1]:
    ans[i]=encpwd[k]

print(''.join(ans))
