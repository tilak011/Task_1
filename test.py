import requests

url = "http://localhost:8000/scan/sql-injection/"
response = requests.post(url)
print(response.json())
