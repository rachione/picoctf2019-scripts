var buffer=[]

var i;
for (i=0; i<8; i++) {
	a=[]
	a.push(i)
	a.push(i)
    buffer.push(a)
}
console.log(i)
for (; i<16; i++) {
	a=[]
	a.push(i)
	a.push(23-i)
    buffer.push(a)
}
console.log(i)
for (; i<32; i+=2) {
	a=[]
	a.push(i)
	a.push(46-i)
    buffer.push(a)
}

for (i=31; i>=17; i-=2) {
	a=[]
	a.push(i)
	a.push(i)
    buffer.push(a)
}
console.log('['+buffer.join(',')+']')