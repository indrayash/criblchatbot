import os
import streamlit as st
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_community.chat_message_histories import StreamlitChatMessageHistory
from langchain.memory import ConversationBufferMemory  # Updated import
from langchain_core.runnables.history import RunnableWithMessageHistory
from langchain_core.prompts import ChatPromptTemplate

# Load Gemini API key from secrets
gemini_key = st.secrets.get("GEMINI_API_KEY")
if not gemini_key:
    st.error("❌ GEMINI_API_KEY not found in secrets.toml.")
    st.stop()

os.environ["GOOGLE_API_KEY"] = "AIzaSyDL7Nbz9yy2MXlGJQXKZIaO2U4gVxxhq2g"

# Initialize Gemini LLM with selected model
llm = ChatGoogleGenerativeAI(model="gemini-1.5-flash", temperature=0.6)

# Setup memory with StreamlitChatMessageHistory
if "chat_history" not in st.session_state:
    st.session_state.chat_history = StreamlitChatMessageHistory()

# Create memory object
memory = ConversationBufferMemory(
    chat_memory=st.session_state.chat_history, 
    return_messages=True
)

# Create system prompt for insider threat detection
system_prompt = """You are a cybersecurity expert specializing in insider threat detection. 
Provide detailed, actionable advice on identifying, preventing, and responding to insider threats. 
Focus on behavioral indicators, technical monitoring, and security best practices."""

prompt_template = ChatPromptTemplate.from_messages([
    ("system", system_prompt),
    ("placeholder", "{history}"),
    ("human", "{input}")
])

# Create conversation chain
chat_chain = RunnableWithMessageHistory(
    prompt_template | llm,
    get_session_history=lambda session_id: st.session_state.chat_history,
    input_messages_key="input",
    history_messages_key="history"
)

# Streamlit UI
st.set_page_config(page_title="Insider Threat Chatbot", page_icon="🛡️")
st.title("🛡️ Insider Threat Detection Chatbot")
st.caption("Ask questions about cybersecurity and insider threat detection")

# Sidebar with options
with st.sidebar:
    st.header("Model Settings")
    model_choice = st.selectbox(
        "Select Gemini Model:",
        ["gemini-1.5-flash", "gemini-1.5-pro", "gemini-1.0-pro"],
        index=0,
        help="gemini-1.5-flash is faster, gemini-1.5-pro is more capable"
    )
    
    st.header("Options")
    if st.button("Clear Chat History"):
        st.session_state.chat_history.clear()
        st.rerun()
    
    st.header("Quick Questions")
    quick_questions = [
        "What are common behavioral indicators of insider threats?",
        "How can I monitor employee access to sensitive data?",
        "What technical controls help prevent insider threats?",
        "How do I investigate a suspected insider threat?"
    ]
    
    for question in quick_questions:
        if st.button(question, key=f"quick_{hash(question)}"):
            st.session_state.selected_question = question

# Display chat messages
for message in st.session_state.chat_history.messages:
    with st.chat_message(message.type):
        st.write(message.content)

# Handle quick question selection
if hasattr(st.session_state, 'selected_question'):
    user_input = st.session_state.selected_question
    delattr(st.session_state, 'selected_question')
else:
    user_input = None

# Chat input
if prompt := st.chat_input("Ask about insider threats..."):
    user_input = prompt

# Process user input
if user_input:
    # Display user message
    with st.chat_message("user"):
        st.write(user_input)
    
    # Generate and display bot response
    with st.chat_message("assistant"):
        with st.spinner("Analyzing security concerns..."):
            try:
                response = chat_chain.invoke(
                    {"input": user_input},
                    config={"configurable": {"session_id": "default"}}
                )
                st.write(response.content)
            except Exception as e:
                error_msg = str(e)
                if "404" in error_msg or "not found" in error_msg.lower():
                    st.error("❌ Model not found. Try selecting a different model from the sidebar.")
                    st.info("Available models: gemini-1.5-flash, gemini-1.5-pro, gemini-1.0-pro")
                elif "api key" in error_msg.lower():
                    st.error("❌ API key issue. Please check your GEMINI_API_KEY in secrets.toml")
                else:
                    st.error(f"Error generating response: {error_msg}")
                st.info("Please check your API key and internet connection.")

# Display some helpful information
if len(st.session_state.chat_history.messages) == 0:
    st.info("""
    👋 Welcome to the Insider Threat Detection Chatbot!
    
    I can help you with:
    - Identifying behavioral indicators of insider threats
    - Implementing technical security controls
    - Developing incident response procedures
    - Understanding compliance requirements
    - Analyzing suspicious activities
    
    Ask me a question or use the quick questions in the sidebar!
    """)
