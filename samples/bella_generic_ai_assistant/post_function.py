def send_http_request(userinput: str) -> dict:
    import requests

    url = 'https://www.shinohack.me/shinollmapp/bella/llmapi'
    headers = {
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.9,ja;q=0.8,zh-TW;q=0.7,zh;q=0.6',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'Origin': 'https://www.shinohack.me',
        'Pragma': 'no-cache',
        'Referer': 'https://www.shinohack.me/shinollmapp/bella/',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36',
        'X-Requested-With': 'XMLHttpRequest',
        'sec-ch-ua': '"Google Chrome";v="137", "Chromium";v="137", "Not/A)Brand";v="24"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"'
    }

    data = {
        'question': userinput
    }

    try:
        response = requests.post(url, headers=headers, data=data)
        return {
            'status_code': response.status_code,
            'html': response.text
        }
    except requests.RequestException as e:
        return {
            'status_code': 0,
            'html': str(e)
        }