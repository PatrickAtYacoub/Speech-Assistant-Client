from signed_call import generate_url
import requests

url = generate_url('http://10.100.100.12:5001/', 'app.llm.db_agents', 'alice', prompt="Which input voltage does procut number 1 have?")

print(url)

response = requests.get(url)

if response.status_code == 200:
    print(response.json())
else:
    print(f"Request failed with status code {response.status_code}")