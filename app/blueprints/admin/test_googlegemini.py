import google.generativeai as genai
import os

genai.configure(api_key='AIzaSyAwIK-pEqrxbJKkJm32qPpqzN_snsZL7m8')

model = genai.GenerativeModel('gemini-1.5-flash')

response = model.generate_content('Hi, how are you')

print(response.text)