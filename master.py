import config
import json

f = open("config.json", "rb")
data = json.loads(f.read())
f.close()
# print (data)
config.lambda_handler(data,1)
