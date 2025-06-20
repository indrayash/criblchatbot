import os
import streamlit as st
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_community.chat_message_histories import StreamlitChatMessageHistory
from langchain.memory import ConversationBufferMemory  # Updated import
from langchain_core.runnables.history import RunnableWithMessageHistory
from langchain_core.prompts import ChatPromptTemplate
import urllib.parse

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

# Enhanced system prompt for log analysis with predictive and prescriptive capabilities
system_prompt = """You are a cybersecurity expert specializing in insider threat detection and log analysis. 
When analyzing logs, provide comprehensive predictive and prescriptive analysis including:

PREDICTIVE ANALYSIS:
- Identify patterns that may indicate potential future security incidents
- Assess risk levels based on observed behaviors and activities
- Predict likely attack vectors or escalation paths
- Estimate probability of insider threat scenarios

PRESCRIPTIVE ANALYSIS:  
- Recommend specific immediate actions to take
- Suggest preventive measures and security controls
- Provide step-by-step incident response procedures
- Recommend monitoring and detection improvements
- Suggest policy and process enhancements

Focus on behavioral indicators, technical monitoring, anomaly detection, and actionable security recommendations.
Always structure your response with clear sections for Predictive Analysis and Prescriptive Analysis."""

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

# Streamlit UI with custom styling
st.set_page_config(
    page_title="Insider Threat Chatbot", 
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for teal and white theme
st.markdown("""
<style>
    /* Main background */
    .stApp {
        background-color: #f0fdfa;
    }
    
    /* Header styling */
    .main-header {
        background: linear-gradient(90deg, #0d9488, #14b8a6);
        padding: 1rem;
        border-radius: 10px;
        margin-bottom: 1rem;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    
    /* Title styling */
    .main-header h1 {
        color: white;
        margin: 0;
        text-align: center;
        font-weight: 600;
    }
    
    /* Subtitle styling */
    .subtitle {
        color: #0f766e;
        text-align: center;
        font-style: italic;
        margin-bottom: 1rem;
    }
    
    /* Sidebar styling */
    .css-1d391kg {
        background-color: white;
    }
    
    /* Chat input styling */
    .stChatInput > div > div {
        background-color: white;
        border: 2px solid #14b8a6;
        border-radius: 10px;
    }
    
    /* Button styling */
    .stButton > button {
        background-color: #14b8a6;
        color: white;
        border: none;
        border-radius: 8px;
        padding: 0.5rem 1rem;
        font-weight: 500;
        transition: all 0.3s ease;
    }
    
    .stButton > button:hover {
        background-color: #0d9488;
        transform: translateY(-2px);
        box-shadow: 0 4px 8px rgba(20, 184, 166, 0.3);
    }
    
    /* Selectbox styling */
    .stSelectbox > div > div {
        background-color: #f3f4f6 !important;
        border: 1px solid #14b8a6;
        border-radius: 8px;
        color: #000000 !important;
    }
    
    /* Selectbox dropdown options */
    .stSelectbox > div > div > div {
        background-color: #f3f4f6 !important;
        color: #000000 !important;
    }
    
    /* Selectbox label text */
    .stSelectbox label {
        color: #000000 !important;
        font-weight: 500;
    }
    
    /* Selectbox selected value text */
    .stSelectbox > div > div > div > div {
        color: #000000 !important;
    }
    
    /* Chat input label */
    .stChatInput label {
        color: #000000 !important;
        font-weight: 500;
    }
    
    /* Chat input placeholder and text */
    .stChatInput input {
        color: #000000 !important;
    }
    
    .stChatInput input::placeholder {
        color: #666666 !important;
    }
    
    /* Chat message text styling */
    .stChatMessage {
        background-color: white;
        border-radius: 10px;
        border: 1px solid #a7f3d0;
        margin: 0.5rem 0;
        color: #000000 !important;
    }
    
    /* All chat message text */
    .stChatMessage * {
        color: #000000 !important;
    }
    
    /* Generated response text */
    .stChatMessage div {
        color: #000000 !important;
    }
    
    /* Markdown text in responses */
    .stChatMessage p, .stChatMessage h1, .stChatMessage h2, .stChatMessage h3, 
    .stChatMessage h4, .stChatMessage h5, .stChatMessage h6, 
    .stChatMessage li, .stChatMessage span {
        color: #000000 !important;
    }
    
    /* Info box styling */
    .stInfo {
        background-color: #e6fffa;
        border-left: 4px solid #14b8a6;
        color: #0f766e;
    }
    
    /* Chat messages styling */
    .stChatMessage {
        background-color: white;
        border-radius: 10px;
        border: 1px solid #a7f3d0;
        margin: 0.5rem 0;
    }
    
    /* User message styling */
    .stChatMessage[data-testid="user"] {
        background-color: #f0fdfa;
        border-left: 4px solid #14b8a6;
    }
    
    /* Assistant message styling */
    .stChatMessage[data-testid="assistant"] {
        background-color: white;
        border-left: 4px solid #0d9488;
    }
    
    /* Sidebar headers */
    .sidebar-header {
        color: #0f766e;
        font-weight: 600;
        font-size: 1.1rem;
        margin-bottom: 0.5rem;
        padding-bottom: 0.5rem;
        border-bottom: 2px solid #a7f3d0;
    }
    
    /* Loading spinner */
    .stSpinner {
        color: #14b8a6;
    }
    
    /* Error styling */
    .stError {
        background-color: #fef2f2;
        border-left: 4px solid #ef4444;
        color: #dc2626;
    }
    
    /* Success styling */
    .stSuccess {
        background-color: #f0fdf4;
        border-left: 4px solid #22c55e;
        color: #16a34a;
    }
    
    /* Webhook status styling */
    .webhook-status {
        background-color: #fef3c7;
        border-left: 4px solid #f59e0b;
        padding: 1rem;
        border-radius: 8px;
        margin: 1rem 0;
    }
</style>
""", unsafe_allow_html=True)

# Custom header
st.markdown("""
<div class="main-header">
    <h1>🛡 Insider Threat Detection & Log Analysis Chatbot</h1>
</div>
""", unsafe_allow_html=True)

st.markdown('<p class="subtitle">Automated log analysis with predictive and prescriptive insights</p>', unsafe_allow_html=True)

# Check for webhook prompt parameter
query_params = st.query_params
webhook_prompt = None

if "prompt" in query_params:
    webhook_prompt = urllib.parse.unquote(query_params["prompt"])
    st.markdown("""
    <div class="webhook-status">
        <strong>🔗 Webhook Request Received</strong><br>
        Processing log analysis request from Cribl Stream...
    </div>
    """, unsafe_allow_html=True)

# Sidebar with options and custom styling
with st.sidebar:
    st.markdown('<h3 class="sidebar-header">🎛 Model Settings</h3>', unsafe_allow_html=True)
    model_choice = st.selectbox(
        "Select Gemini Model:",
        ["gemini-1.5-flash", "gemini-1.5-pro", "gemini-1.0-pro"],
        index=0,
        help="gemini-1.5-flash is faster, gemini-1.5-pro is more capable"
    )
    
    st.markdown('<h3 class="sidebar-header">⚙ Options</h3>', unsafe_allow_html=True)
    if st.button("🗑 Clear Chat History", use_container_width=True):
        st.session_state.chat_history.clear()
        st.rerun()
    
    # Webhook status indicator
    st.markdown('<h3 class="sidebar-header">🔗 Webhook Status</h3>', unsafe_allow_html=True)
    if webhook_prompt:
        st.success("✅ Webhook request active")
        st.info(f"Analyzing {len(webhook_prompt)} characters of log data")
    else:
        st.info("⏳ Waiting for webhook requests")
    
    st.markdown('<h3 class="sidebar-header">💡 Quick Questions</h3>', unsafe_allow_html=True)
    quick_questions = [
        "What are common behavioral indicators of insider threats?",
        "How can I monitor employee access to sensitive data?",
        "What technical controls help prevent insider threats?",
        "How do I investigate a suspected insider threat?",
        "Analyze recent login patterns for anomalies",
        "What are the key metrics for insider threat detection?"
    ]
    
    for i, question in enumerate(quick_questions):
        if st.button(f"❓ {question}", key=f"quick_{i}", use_container_width=True):
            st.session_state.selected_question = question

# Display chat messages
for message in st.session_state.chat_history.messages:
    with st.chat_message(message.type):
        st.write(message.content)

# Handle webhook prompt automatically
if webhook_prompt and "webhook_processed" not in st.session_state:
    st.session_state.webhook_processed = True
    user_input = webhook_prompt
    
    # Display webhook prompt as user message
    with st.chat_message("user"):
        st.write("🔗 *Webhook Log Analysis Request:*")
        st.code(webhook_prompt, language="text")
    
    # Generate and display bot response
    with st.chat_message("assistant"):
        with st.spinner("🔍 Performing predictive and prescriptive log analysis..."):
            try:
                response = chat_chain.invoke(
                    {"input": user_input},
                    config={"configurable": {"session_id": "webhook_session"}}
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

# Handle quick question selection
elif hasattr(st.session_state, 'selected_question'):
    user_input = st.session_state.selected_question
    delattr(st.session_state, 'selected_question')
else:
    user_input = None

# Chat input (disabled when webhook is processing)
if webhook_prompt:
    st.chat_input("Webhook request is being processed...", disabled=True)
else:
    if prompt := st.chat_input("Ask about insider threats or paste logs for analysis..."):
        user_input = prompt

# Process regular user input (non-webhook)
if user_input and not webhook_prompt:
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

# Reset webhook processing flag when URL changes
if not webhook_prompt and "webhook_processed" in st.session_state:
    del st.session_state.webhook_processed

# Display helpful information with custom styling
if len(st.session_state.chat_history.messages) == 0 and not webhook_prompt:
    st.markdown("""
    <div style="background: linear-gradient(135deg, #e6fffa 0%, #f0fdfa 100%); 
                padding: 2rem; 
                border-radius: 15px; 
                border: 2px solid #a7f3d0; 
                margin: 1rem 0;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);">
        <h2 style="color: #0f766e; text-align: center; margin-bottom: 1rem;">
            👋 Welcome to the Enhanced Log Analysis Chatbot!
        </h2>
        <div style="color: #0f766e; font-size: 1.1rem; line-height: 1.6;">
            <p><strong>I can help you with:</strong></p>
            <ul style="padding-left: 1.5rem;">
                <li>🔍 <strong>Predictive Analysis:</strong> Identify patterns and predict potential security incidents</li>
                <li>📋 <strong>Prescriptive Analysis:</strong> Provide actionable recommendations and response procedures</li>
                <li>🛡 Detecting behavioral indicators of insider threats</li>
                <li>📊 Analyzing log data from Cribl Stream via webhook integration</li>
                <li>🔎 Investigating suspicious activities and anomalies</li>
                <li>⚡ Real-time log analysis and threat assessment</li>
            </ul>
            <p><strong>🔗 Webhook Integration Active:</strong> Ready to receive and analyze logs from Cribl Stream</p>
            <p><strong>Ask me a question, use quick questions, or send logs via webhook!</strong></p>
        </div>
    </div>
    """, unsafe_allow_html=True)
