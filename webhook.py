import streamlit as st
from langchain.chat_models import ChatOpenAI
from langchain.chains import ConversationChain
from langchain.memory import ConversationBufferMemory

import os
os.environ["OPENAI_API_KEY"] = "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"

st.set_page_config(page_title="Threat Detection Chatbot")

st.title("🔐 Internal Threat Detection Chatbot")

# Initialize chat model
llm = ChatOpenAI(temperature=0.6, model_name="gpt-3.5-turbo")

# Set up memory for conversation
memory = ConversationBufferMemory()

# Create the conversation chain
conversation = ConversationChain(llm=llm, memory=memory, verbose=False)

# Chat UI
user_input = st.text_input("Ask your threat detection question 👇")

if user_input:
    response = conversation.predict(input=user_input)
    st.write(f"🧠 Bot: {response}")