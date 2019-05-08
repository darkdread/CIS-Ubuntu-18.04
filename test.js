window.BGR = {
    blue: 0,
    green: 0,
    red: 0,
};

function getBGR(value){
    let blue, green, red = 0;

    blue = Math.floor(value / 65536);
    green = Math.floor((value - (blue * 65536)) / 256);
    red = Math.floor(value - (blue * 65536) - (green * 256));

    window.BGR = {
        blue: blue,
        green: green,
        red: red,
    };

    console.log(window.BGR);
}

getBGR(255*65536 + 255*256 + 255);