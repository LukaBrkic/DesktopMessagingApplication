#include "../inc/ClientApp.h"
#include "../inc/Util.h"

#include <iostream>
#include <chrono>

#define PORT 1325


using namespace std::chrono_literals;

ClientApp::ClientApp() : 
    m_client("127.0.0.1", PORT, *this)
{
    m_app = App::Create();
    m_app->set_listener(this);

    m_window = Window::Create(m_app->main_monitor(), 1080, 720,
        false, kWindowFlags_Titled | kWindowFlags_Maximizable);
    m_window->SetTitle("MessagingAplikacija");
    m_window->set_listener(this);

    m_app->set_window(*m_window.get());
    m_userView = Overlay::Create(*m_window.get(), 1, 1, 0, 0);
    m_userView->view()->LoadURL("file:///loginForm.html");
    m_userView->view()->Focus();
    OnResize(m_window->width(), m_window->height());
    m_userView->view()->set_view_listener(this);
    m_userView->view()->set_load_listener(this);
    m_client.start();
}


void ClientApp::OnResize(uint32_t width, uint32_t height) {
    m_userView->Resize((uint32_t)width, height);
    m_userView->MoveTo(0, 0);
}

std::string ClientApp::jsStringToStdString(JSString&& jsString)
{
    return std::string(static_cast<ultralight::String>(jsString).utf8().data());
}

void ClientApp::sendRegistrationMessage(const JSObject& jsObject, const JSArgs& args)
{
    m_clientUsername = jsStringToStdString(args[0]);
    m_client.sendRegistrationMessage(jsStringToStdString(args[0]), jsStringToStdString(args[1]), jsStringToStdString(args[2]), jsStringToStdString(args[3]));
}

void ClientApp::sendResetPasswordMessage(const JSObject& jsObject, const JSArgs& args)
{
    m_client.sendResetPasswordMessage(jsStringToStdString(args[0]), jsStringToStdString(args[1]), jsStringToStdString(args[2]), jsStringToStdString(args[3]));
}

void ClientApp::sendLoginMessage(const JSObject& jsObject, const JSArgs& args)
{
    m_clientUsername = jsStringToStdString(args[0]);
    m_client.sendLoginMessage(jsStringToStdString(args[0]), jsStringToStdString(args[1]));
}

void ClientApp::sendTextMessage(const JSObject& jsObject, const JSArgs& args)
{
    m_client.sendTextMessage(jsStringToStdString(args[0]), jsStringToStdString(args[1]));
}

void ClientApp::goToMainScreen()
{
    m_userView->view()->LoadURL("file:///index.html");
}

void ClientApp::goToLoginScreenAfterSuccessfulRegistration()
{
    m_userView->view()->LoadURL("file:///loginFormAfterSuccessfulRegistration.html");
}

void ClientApp::OnUpdate()
{
    if (m_clientState == 0 && (m_clientStatePrev == 1 || m_clientStatePrev == 2) && loaded)
    {
        setClientUsernameAfterRegistration(m_clientUsername);
    }
    if (m_clientState == 1) // client registered
    {
        goToLoginScreenAfterSuccessfulRegistration();
        m_clientStatePrev = m_clientState;
        m_clientState = 0;
    }
    else if (m_clientState == 2) // client logged in 
    {
        goToMainScreen();
        m_clientStatePrev = m_clientState;
        m_clientState = 0;
    }
    if (!m_messagesToDisplay.empty())
    {
        handleMessage(m_messagesToDisplay.popFront());
    }
    loaded = false;
}

void ClientApp::OnChangeCursor(ultralight::View* caller, Cursor cursor)
{
    m_window->SetCursor(cursor);
}

void ClientApp::handleMessage(const Message& message)
{
    if (message.messageType == MessageType::TextMessage)
    {
        std::string username, textMessage;
        Util::extractUsernameAndMessage(message.messageContent, username, textMessage);
        std::cout << textMessage << std::endl;
        displayMessage(username, textMessage);
    }
    else if (message.messageType == MessageType::FriendRequest)
    {
        if (message.messageContent[0] == 'T')
            m_friendExists({});
        else
            m_friendDoesNotExist({});
    }
}

void ClientApp::SetState(int state)
{
    m_clientState = state;
}

std::string ClientApp::getClientUsername() const
{
    return m_clientUsername;
}

void ClientApp::displayMessage(const std::string& fromUser, const std::string& textMessage)
{
    m_displayMessage({ JSString(fromUser.c_str()), JSString(textMessage.c_str()) });
}

void ClientApp::setClientUsernameAfterRegistration(const std::string& clientUsername)
{
    m_setClientUsernameAfterRegistration({ JSString(clientUsername.c_str())});
}


void ClientApp::pushMessage(const Message& message)
{
    m_messagesToDisplay.insertBack(message);
}

void ClientApp::checkIfFriendExists(const JSObject& jsObject, const JSArgs& args)
{
    m_client.checkIfFriendExists(jsStringToStdString(args[0]));
}

void ClientApp::setLanguage(const JSObject& jsObject, const JSArgs& args)
{
    m_lang = jsStringToStdString(args[0]);
}

void ClientApp::deleteAccount(const JSObject& jsObject, const JSArgs& args)
{
    m_client.deleteAccount();
    m_userView->view()->LoadURL("file:///loginForm.html");
}


void ClientApp::OnDOMReady(ultralight::View* caller,
    uint64_t frame_ide,
    bool is_main_frame,
    const ultralight::String& url) 
{
    Ref<JSContext> context = caller->LockJSContext();
    SetJSContext(context.get());

    JSObject global = JSGlobalObject();

    global["sendRegistrationMessage"] = BindJSCallback(&ClientApp::sendRegistrationMessage);
    global["sendLoginMessage"] = BindJSCallback(&ClientApp::sendLoginMessage);
    global["sendTextMessage"] = BindJSCallback(&ClientApp::sendTextMessage);
    global["checkIfFriendExists"] = BindJSCallback(&ClientApp::checkIfFriendExists);
    global["sendResetPasswordMessage"] = BindJSCallback(&ClientApp::sendResetPasswordMessage);
    global["setLanguage"] = BindJSCallback(&ClientApp::setLanguage);
    global["cppDeleteAccount"] = BindJSCallback(&ClientApp::deleteAccount);
    m_friendExists = global["friendExists"];
    m_getLanguage = global["getLanguage"];
    m_friendDoesNotExist = global["friendDoesNotExist"];
    m_setClientUsernameAfterRegistration = global["setClientUsernameAfterRegistration"];
    m_displayMessage = global["displayMessage"];
    loaded = true;
    m_getLanguage({ JSString(m_lang.c_str()) });
}


void ClientApp::OnClose() {}

void ClientApp::run() 
{
    m_app->Run();
}
