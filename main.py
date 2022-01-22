import json
import threading
import urllib.parse
import socket
import requests
import websocket
import re
import webbrowser


def verifyToken(token, clientid):
    vr = requests.get("https://id.twitch.tv/oauth2/validate", headers={"Authorization": "Bearer " + token})
    content = vr.json()
    if "status" in content and content["status"] == 401:
        return False
    else:
        return content


def createAppAccessToken(clientid, secret):
    caatr = requests.post("https://id.twitch.tv/oauth2/token",
                          params={"client_id": clientid, "client_secret": secret, "grant_type": "client_credentials"})
    return caatr.json()


def exchangeAuthorizationCodeForUserToken(code, clientid, secret):
    eacfutr = requests.post("https://id.twitch.tv/oauth2/token",
                            params={"client_id": clientid, "client_secret": secret, "code": code,
                                    "grant_type": "authorization_code", "redirect_uri": "http://localhost:8337"})
    return eacfutr.json()


def saveConfig():
    with open("config.json", "w") as f:
        f.write(json.dumps(config))
    print("Config saved.")


def setReadOnlyTrue():
    global readOnly, username
    readOnly = True
    # You can use "justinfan" followed by any 4 digits to connect to chat anonymously and only READ chat.
    username = "justinfan1337"


def onChatMessage(wsapp, message):
    for line in message.splitlines():
        # handle all incoming lines by twitch
        if (config["debug"]):  # print all lines if we have debug enabled.
            print(line)
        if (line.startswith("PING")):
            wsapp.send(line.replace("PING", "PONG"))
        # Regexes courtesy of BarryCarlyon https://github.com/BarryCarlyon/twitch_misc/blob/main/chat/chat.js#L46
        ircMessage = re.match(r"^(?:@([^ ]+) )?(?:[:](\S+) )?(\S+)(?: (?!:)(.+?))?(?: [:](.+))?$", line)
        # 0 is the unparsed message
        # 1 ircV3 tags
        # 2 host/user
        # 3 COMMAND
        # 4 room
        # 5 remainder / the actual message

        # we want to know who sent a message
        hostMatch = re.match(r"([a-z_0-9]+)!([a-z_0-9]+)@([a-z._0-9]+)", ircMessage.group(2))
        user = hostMatch.group(
            1)  # on twitch, the username before and after the ! are the same, but may be different on "normal" IRC servers.
        # we could parse out more info in the messages here, but that's outside the scope of this example.

        usermessage = ircMessage.group(5)
        channel = ircMessage.group(4)

        print(channel + " " + user + ": " + usermessage)

        # now we can handle commands
        if usermessage.startswith("!echo"):
            if (not readOnly): # we can only reply if we are not read-only!
                wsapp.send("PRIVMSG " + channel + " :" + usermessage.replace("!echo ", ""))


def onChatConnect(wsapp):
    print("Connected to Twitch Chat via WS")
    # upon connection, we want to request certain Capabilities for information’s sake and then log in, depending on if we
    # are read-only or actually authenticated.
    wsapp.send("CAP REQ :twitch.tv/tags")
    wsapp.send("CAP REQ :twitch.tv/commands")
    if not readOnly:
        wsapp.send("PASS oauth:" + currentToken)
    wsapp.send("NICK " + username)
    wsapp.send("JOIN #marenthyu")


if __name__ == '__main__':
    # read required config values
    with open("config.json") as f:
        config = json.loads(f.read())
        if not "clientid" in config:
            print("clientid missing in config.json, please provide it.")
            exit(1)
        if not "secret" in config:
            print("secret missing in config.json, please provide it.")
            exit(1)

    # verify if we have a valid token
    verifyResponse = verifyToken(config["lasttoken"], config["clientid"])
    if not verifyResponse:
        print("Token invalid, need a new token...")
        if config["usertoken"]:
            print(
                "Opening your default webbrowser so you can sign in with Twitch; Will listen on port 8337 to get the response.")
            print("Please make sure you have \"http://localhost:8337\" added as a redirect URI on your Dev Dashboard.")
            webbrowser.open("https://id.twitch.tv/oauth2/authorize?" + urllib.parse.urlencode(
                {"redirect_uri": "http://localhost:8337", "client_id": config["clientid"], "response_type": "code",
                 "scope": "chat:edit chat:read"}))
            with socket.socket() as s:
                s.bind(("127.0.0.1", 8337))
                s.listen()
                print("Waiting for request...")
                conn, addr = s.accept()
                with conn:
                    print("Got a connection...")
                    data = ""
                    while True:
                        currdata = conn.recv(1024)
                        if not currdata:
                            break
                        if config["debug"]:
                            print("Got: " + str(currdata.decode('utf-8')))
                        data += str(currdata.decode('utf-8'))
                        if data.endswith("\r\n\r\n"):  # means we are at the end of the header request
                            break
                    # we expect a browser to be requesting the root page, but all we really care about is the code which is included in the first line.
                    # For more info, look into how HTTP works.
                    firstline = data.splitlines()[0]
                    code = re.match(r"GET /\?code=(?P<code>.*)&scope=(?P<scopes>.*) HTTP/(?P<version>.*)",
                                    firstline).group("code")
                    print("Got code " + code + " from browser!")
                    responseContent = "Thank you, code received".encode("utf-8")
                    conn.sendall((
                                             "HTTP/1.1 200 OK\r\nHost: localhost\r\nServer: MarenthyuTwitchPYthonExample/1.1\r\nContent-Type: text/plain\r\nContent-Length: " + str(
                                         len(responseContent)) + "\r\n\r\n").encode("utf-8") + responseContent)
                print("Connection closed.")
            print("Socket closed.")
            print("Exchanging code for token...")
            newtokenresponse = exchangeAuthorizationCodeForUserToken(code, config["clientid"], config["secret"])
        else:
            newtokenresponse = createAppAccessToken(config["clientid"], config["secret"])
        # print("New Token Response: " + json.dumps(newtokenresponse))
        # Don't leak your token :)
        config["lasttoken"] = newtokenresponse["access_token"]
        saveConfig()
        verifyResponse = verifyToken(config["lasttoken"], config["clientid"])
        print("Renewed token info: " + json.dumps(verifyResponse))
    else:
        print("Token valid! Response was " + json.dumps(verifyResponse))
    currentToken = config["lasttoken"]

    if "user_id" not in verifyResponse:
        if config["usertoken"]:
            print(
                "The provided token is an App Access Token, but you requested an App Access Token. Please delete the \"lasttoken\" from the config and start again.")
            exit(1)
        else:
            print(
                "The provided token is only an App Access Token / Client Credentials Token, so we will connect to chat in read-only mode.")
            setReadOnlyTrue()
    elif not ("scopes" in verifyResponse and "chat:read" in verifyResponse["scopes"] and "chat:edit" in verifyResponse[
        "scopes"]):
        print(
            "The provided token is missing the required scopes to read and edit chat, so we will connect to chat in read-only mode.")
        setReadOnlyTrue()
    else:
        readOnly = False
        username = verifyResponse["login"]

    # Everything should be ready, so we connect to chat!
    wsapp = websocket.WebSocketApp("wss://irc-ws.chat.twitch.tv:443", on_message=onChatMessage, on_open=onChatConnect)
    t = threading.Thread(
        target=wsapp.run_forever)  # the run_forever method blocks the thread it is running on, so we start it in a new thread.
    t.start()
