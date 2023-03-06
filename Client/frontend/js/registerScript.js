function tryRegisterJS() {
    var username = document.getElementById("username").value;
    var secretWord = document.getElementById("secretWord").value;
    var psw = document.getElementById("psw").value;
    var pswRepeat = document.getElementById("psw-repeat").value;
    sendRegistrationMessage(username, secretWord, psw, pswRepeat);
}