

import openai


client = openai.OpenAI(api_key='sk-proj-cZ64BNWia1iH5uWfd0VDT3BlbkFJBwsFscvNFLL2gsCYVlTs')

# def chat_with_gpt(prompt):
#
#     messages = []
#     messages.append({"role": "system",
#                      "content": """You are a recipe creator.
#                        Ignore all unrelated inputs, and only output recipe in
#                        the following format: Name, description (Put in the other details
#                        inside like calories, and other things the user specifies."""})
#     print('AI Recipe Creator Activating')
#
#     messages.append({"role": "user", "content": prompt})
#
#     completion = client.chat.completions.create(
#         model="gpt-3.5-turbo",
#         messages=messages
#     )
#
#     reply = completion["choices"][0]["message"]
#     return reply

def chat_with_gpt(prompt):

    messages = []

    messages.append({"role": "user", "content": prompt})

    completion = client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=messages
    )

    reply = completion["choices"][0]["message"]
    return reply


if __name__ == "__main__":
    while True:
        user_input = input('You: ')
        if user_input.lower() in ["quit","exit","bye"]:
            break

        response = chat_with_gpt(user_input)
        print("AI: ", response)

