#pragma once

#include <AppCore/App.h>
#include <AppCore/Window.h>
#include <AppCore/Overlay.h>
#include <AppCore/JSHelpers.h>
#include "Client.h"

using namespace ultralight;


class ClientApp : public WindowListener, public ViewListener, public LoadListener, public AppListener {

public:
    ClientApp();

    std::string jsStringToStdString(JSString&& jsString);

    void sendRegistrationMessage(const JSObject& jsObject, const JSArgs& args);
    void sendResetPasswordMessage(const JSObject& jsObject, const JSArgs& args);
    void sendLoginMessage(const JSObject& jsObject, const JSArgs& args);
    void sendTextMessage(const JSObject& jsObject, const JSArgs& args);
    void checkIfFriendExists(const JSObject& jsObject, const JSArgs& args);
    void setLanguage(const JSObject& jsObject, const JSArgs& args);
    void deleteAccount(const JSObject& jsObject, const JSArgs& args);
    

    virtual void OnChangeCursor(ultralight::View* caller, Cursor cursor) override;

    void displayMessage(const std::string& fromUser, const std::string& textMessage);
    void setClientUsernameAfterRegistration(const std::string& clientUsername);
    void handleMessage(const Message& message);

    void pushMessage(const Message& message);

    virtual void OnDOMReady(ultralight::View* caller,
                            uint64_t frame_ide,
                            bool is_main_frame,
                            const ultralight::String& url) override;

    virtual void OnResize(uint32_t width, uint32_t height) override;
    virtual void OnClose() override;
    virtual void OnUpdate() override;
    void run();
    void goToMainScreen();
    void goToLoginScreenAfterSuccessfulRegistration();

    void SetState(int state);

    std::string getClientUsername() const;

    virtual ~ClientApp() {}

private:
    void setLoginListener();

    RefPtr<App> m_app;
    RefPtr<Window> m_window;
    RefPtr<Overlay> m_userView;
    Client m_client;
    JSFunction m_displayMessage;
    JSFunction m_friendExists;
    JSFunction m_friendDoesNotExist;
    JSFunction m_setClientUsernameAfterRegistration;
    JSFunction m_getLanguage;
    ThreadSafeQueue m_messagesToDisplay;
    std::string m_clientUsername;
    int m_clientState;
    int m_clientStatePrev;
    bool loaded = false;
    std::string m_lang = "ENG";
};
