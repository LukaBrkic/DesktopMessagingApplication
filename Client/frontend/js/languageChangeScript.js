var language = "ENG";
function changeLanguage() {
    // change from english to croatian
    if (language == "ENG") {
        language = "HRV";
        setCroatian();
    }
    // change from croatian to english
    else if (language == "HRV") {
        language = "ENG";
        setEnglish();
    }
    setLanguage(language);

}
// set language when changind a view
function getLanguage(languageTemp) {
    language = languageTemp;
    if (language == "ENG")
        setEnglish();
    else
        setCroatian();
}