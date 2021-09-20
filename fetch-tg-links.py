#!/bin/env python3

from ctypes.util import find_library
from ctypes import *
import json
import sys
import os
import pprint
import requests
import asyncio
from functools import reduce
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from collections import defaultdict
import argparse


def load_tdlib():
    # load shared library
    curr_dir = os.path.dirname(os.path.realpath(__file__))
    # tdjson_path = os.path.join(curr_dir, "td", "build", "libtdjson.so")
    tdjson_path = find_library("tdjson") or "tdjson.dll"
    if tdjson_path is None:
        print("can't find tdjson library", file=sys.stderr)
        quit()
    tdjson = CDLL(tdjson_path)
    # load TDLib functions from shared library
    _td_create_client_id = tdjson.td_create_client_id
    _td_create_client_id.restype = c_int
    _td_create_client_id.argtypes = []

    _td_receive = tdjson.td_receive
    _td_receive.restype = c_char_p
    _td_receive.argtypes = [c_double]

    _td_send = tdjson.td_send
    _td_send.restype = None
    _td_send.argtypes = [c_int, c_char_p]

    _td_execute = tdjson.td_execute
    _td_execute.restype = c_char_p
    _td_execute.argtypes = [c_char_p]

    log_message_callback_type = CFUNCTYPE(None, c_int, c_char_p)

    _td_set_log_message_callback = tdjson.td_set_log_message_callback
    _td_set_log_message_callback.restype = None
    _td_set_log_message_callback.argtypes = [c_int, log_message_callback_type]

    # initialize TDLib log with desired parameters
    def on_log_message_callback(verbosity_level, message):
        if verbosity_level == 0:
            print("TDLib fatal error: ", message, file=sys.stderr)
            sys.stdout.flush()

    def td_execute(query):
        query = json.dumps(query).encode("utf-8")
        result = _td_execute(query)
        if result:
            result = json.loads(result.decode("utf-8"))
        return result

    c_on_log_message_callback = log_message_callback_type(on_log_message_callback)
    _td_set_log_message_callback(2, c_on_log_message_callback)

    # setting TDLib log verbosity level to 1 (errors)
    td_execute(
        {
            "@type": "setLogVerbosityLevel",
            "new_verbosity_level": 1,
            "@extra": 1.01234,
        }
    )

    # create client
    client_id = _td_create_client_id()

    def td_send(query):
        query = json.dumps(query).encode("utf-8")
        _td_send(client_id, query)

    def td_receive():
        result = _td_receive(1.0)
        if result:
            result = json.loads(result.decode("utf-8"))
        return result

    return td_send, td_receive


td_send, td_receive = load_tdlib()


# process authorization states
def process_auth_flow(event):
    if event["@type"] == "updateAuthorizationState":
        auth_state = event["authorization_state"]

        # if client is closed, we need to destroy it and create new client
        if auth_state["@type"] == "authorizationStateClosed":
            return False

        # set TDLib parameters
        # you MUST obtain your own api_id and api_hash at https://my.telegram.org
        # and use them in the setTdlibParameters call
        if auth_state["@type"] == "authorizationStateWaitTdlibParameters":
            td_send(
                {
                    "@type": "setTdlibParameters",
                    "parameters": {
                        "database_directory": "tdlib",
                        "use_message_database": True,
                        "use_secret_chats": True,
                        "api_id": 94575,
                        "api_hash": "a3406de8d171bb422bb6ddf3bbd800e2",
                        "system_language_code": "en",
                        "device_model": "Desktop",
                        "application_version": "1.0",
                        "enable_storage_optimizer": True,
                    },
                }
            )

        # set an encryption key for database to let know TDLib how to open the database
        if auth_state["@type"] == "authorizationStateWaitEncryptionKey":
            td_send({"@type": "checkDatabaseEncryptionKey", "encryption_key": ""})

        # enter phone number to log in
        if auth_state["@type"] == "authorizationStateWaitPhoneNumber":
            phone_number = input("Please enter your phone number: ")
            td_send(
                {
                    "@type": "setAuthenticationPhoneNumber",
                    "phone_number": phone_number,
                }
            )

        # wait for authorization code
        if auth_state["@type"] == "authorizationStateWaitCode":
            code = input("Please enter the authentication code you received: ")
            td_send({"@type": "checkAuthenticationCode", "code": code})

        # wait for first and last name for new users
        if auth_state["@type"] == "authorizationStateWaitRegistration":
            first_name = input("Please enter your first name: ")
            last_name = input("Please enter your last name: ")
            td_send(
                {
                    "@type": "registerUser",
                    "first_name": first_name,
                    "last_name": last_name,
                }
            )

        # wait for password if present
        if auth_state["@type"] == "authorizationStateWaitPassword":
            password = input("Please enter your password: ")
            td_send({"@type": "checkAuthenticationPassword", "password": password})

    return True


loggedIn = False


def githubHandler(username: str):
    if len(username.strip()) == 0:
        return
    url = f"https://www.github.com/{username}"
    resp = requests.get(url)
    if resp.status_code == 200:
        print(f"FOUND GITHUB for {username}: {url}")
        return url
    return None


githubHandler.__netName = "github"

networks = [githubHandler]


def check_all_user_networks(state, username: str):
    user: dict = dict()
    state.users[username] = user
    for net in networks:
        user[net.__netName] = net(username)


@dataclass
class State:
    users: Dict[str, Dict[str, Optional[str]]] = field(default_factory=dict)

    def save_to(self, out_file: str):
        with open(out_file, "w") as f:
            json.dump({"users": self.users}, f)


# main events cycle
def fetch_user_links(channel_name, channel_id=None, start_from=None):
    global loggedIn

    # start the client by sending request to it
    td_send({"@type": "getAuthorizationState", "@extra": 1.01234})

    pp = pprint.PrettyPrinter(indent=4)
    need_new_members = True
    user_offset = 0 if start_from is None else start_from
    state = State()

    try:
        while True:
            event = td_receive()
            if event:
                b = process_auth_flow(event)
                if not b:
                    break
                if event["@type"] == "ok" and not loggedIn:
                    loggedIn = True
                elif event["@type"] == "error":
                    print("ERROR:", event, file=sys.stderr)
                    return
                elif channel_id is None and event["@type"] == "updateSupergroup":
                    if event["supergroup"]["username"] == channel_name:
                        print("SET CHANNEL ID")
                        channel_id = event["supergroup"]["id"]
                elif loggedIn and channel_id is not None and need_new_members:
                    to_fetch = 10
                    td_send(
                        {
                            "@type": "getSupergroupMembers",
                            "supergroup_id": channel_id,
                            "offset": user_offset,
                            "limit": to_fetch,
                        }
                    )
                    print(
                        f"Fetching a batch of {to_fetch} users with an offset of {user_offset}"
                    )
                    need_new_members = False
                    user_offset += to_fetch
                    users_to_process = to_fetch
                elif event["@type"] == "chatMembers":
                    for member in event["members"]:
                        member_id = member["member_id"]["user_id"]
                        td_send({"@type": "getUser", "user_id": member_id})
                elif event["@type"] == "user":
                    username = event["username"]
                    if len(username.strip()) != 0:
                        print("Processing user", username)
                        check_all_user_networks(state, username)
                    if users_to_process == 1:
                        need_new_members = True
                    else:
                        users_to_process -= 1
    except KeyboardInterrupt:
        pass

    # Print results
    users = state.users
    links_count_per_net = defaultdict(int)
    links_found = 0
    for _, user in users.items():
        for net, url in user.items():
            if url is None:
                continue
            links_found += 1
            links_count_per_net[net] += 1
    links_count_per_net_s = ", ".join(
        [f"{a}={b}" for a, b in links_count_per_net.items()]
    )
    users_processed = len(users)
    print()
    print(
        f"DONE. Processed {users_processed} users. Found {links_found} links ({links_count_per_net_s})"
    )
    print(f"Last position: {user_offset}")

    return state


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Fetch Telegram group chat member links"
    )
    ngroup = parser.add_mutually_exclusive_group(required=True)
    ngroup.add_argument("--name", help="Channel name")
    ngroup.add_argument("--id", help="Channel id (overrides the channel name)")
    parser.add_argument("--offset", help="Chat member offset", type=int)
    parser.add_argument("--out", help="Output file")
    args = parser.parse_args()
    channel_name = args.name
    channel_id = args.id
    start_from = args.offset
    out = args.out
    state = fetch_user_links(channel_name, channel_id, start_from)
    if out is not None:
        print(f"Saving to {out}... ", end="")
        state.save_to(out)
        print("Done!")
