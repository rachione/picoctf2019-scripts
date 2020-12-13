
var keysets = [[5, 5, 3, 0, 3, 6, 2, 1, 4, 5, 3, 6, 2, 2, 3, 3]]
var currentIndex = 0;
var currentKey = keysets[0];




function nextKey() {
    currentIndex++;
    currentKey = keysets[currentIndex]
}


function assemble_png(u_in) {
    var LEN = 16;
    var result = [];
    for (var i = 0; i < LEN; i++) {
        shifter = u_in[i]
        for (var j = 0; j < (bytes.length / LEN); j++) {
            result[(j * LEN) + i] = bytes[(((j + shifter) * LEN) % bytes.length) + i]
        }
    }
    while (result[result.length - 1] == 0) {
        result = result.slice(0, result.length - 1);
    }
    document.getElementById("Area").src = "data:image/png;base64," + btoa(String.fromCharCode.apply(null, new Uint8Array(result)));
    return false;
}



$("#Area").on("error", function () {
  
});


$("#Area").on("load", function () {
    console.log('keys:' + currentKey)
});


assemble_png(currentKey)