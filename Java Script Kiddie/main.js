

var currentIndex = 0;
var currentKey = "0000000000000000";


function pad(num) {
    y = '00000000000000000000000000000' + num;
    return y.substr(y.length - 16);
}

function nextKey() {
    currentIndex++;
    currentKey = pad(currentIndex)
}


function assemble_png(u_in) {

    var LEN = 16;
    var key = "0000000000000000";
    var shifter;
    if (u_in.length == LEN) {
        key = u_in;
    }
    var result = [];
    for (var i = 0; i < LEN; i++) {
        shifter = key.charCodeAt(i) - 48;
        for (var j = 0; j < (bytes.length / LEN); j++) {
            result[(j * LEN) + i] = bytes[(((j + shifter) * LEN) % bytes.length) + i]
        }
    }
    while (result[result.length - 1] == 0) {
        result = result.slice(0, result.length - 1);
    }
    Area.src = "data:image/png;base64," + btoa(String.fromCharCode.apply(null, new Uint8Array(result)));
}



$("#Area").on("error", function () {
    nextKey()
    assemble_png(currentKey)
});


$("#Area").on("load", function () {
    console.log('keys:' + currentKey)
});


assemble_png(currentKey)