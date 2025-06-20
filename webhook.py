import os
import streamlit as st
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_community.chat_message_histories import StreamlitChatMessageHistory
from langchain.memory import ConversationBufferMemory
from langchain_core.runnables.history import RunnableWithMessageHistory
from langchain_core.prompts import ChatPromptTemplate
import urllib.parse
import json
from datetime import datetime
import re

# Load Gemini API key from secrets
gemini_key = st.secrets.get("GEMINI_API_KEY")
if not gemini_key:
    st.error("❌ GEMINI_API_KEY not found in secrets.toml.")
    st.stop()

os.environ["GOOGLE_API_KEY"] = gemini_key

# Initialize analysis results storage in session state
if "analysis_results" not in st.session_state:
    st.session_state.analysis_results = {}

# Initialize processed webhooks tracking
if "processed_webhooks" not in st.session_state:
    st.session_state.processed_webhooks = set()

# Initialize Gemini LLM with selected model
@st.cache_resource
def get_llm(model_name):
    return ChatGoogleGenerativeAI(model=model_name, temperature=0.6)

# Setup memory with StreamlitChatMessageHistory
if "chat_history" not in st.session_state:
    st.session_state.chat_history = StreamlitChatMessageHistory()

# Create memory object
memory = ConversationBufferMemory(
    chat_memory=st.session_state.chat_history, 
    return_messages=True
)

# Enhanced system prompt for log analysis
system_prompt = """You are an expert cybersecurity analyst specializing in insider threat detection and log analysis. 
When analyzing logs, provide comprehensive analysis including:

PREDICTIVE ANALYSIS:
- Identify patterns that may indicate potential future security incidents
- Assess risk levels (LOW/MEDIUM/HIGH/CRITICAL) based on observed behaviors
- Predict likely attack vectors or escalation paths
- Estimate probability of insider threat scenarios

PRESCRIPTIVE ANALYSIS:  
- Recommend specific immediate actions to take
- Suggest preventive measures and security controls
- Provide step-by-step incident response procedures
- Recommend monitoring and detection improvements
- Suggest policy and process enhancements

STRUCTURED RESPONSE FORMAT:
🚨 *THREAT LEVEL*: [LOW/MEDIUM/HIGH/CRITICAL]
📊 *RISK SCORE*: [1-10]
🔍 *KEY FINDINGS*: Brief summary
⚡ *IMMEDIATE ACTIONS*: Critical next steps
🛡 *RECOMMENDATIONS*: Long-term improvements

Focus on behavioral indicators, technical monitoring, anomaly detection, and actionable security recommendations."""

prompt_template = ChatPromptTemplate.from_messages([
    ("system", system_prompt),
    ("placeholder", "{history}"),
    ("human", "{input}")
])

# Streamlit UI configuration
st.set_page_config(
    page_title="Insider Threat Chatbot", 
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .stApp {
        background-color: #f0fdfa;
    }
    
    .main-header {
        background: linear-gradient(90deg, #0d9488, #14b8a6);
        padding: 1rem;
        border-radius: 10px;
        margin-bottom: 1rem;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    
    .main-header h1 {
        color: white;
        margin: 0;
        text-align: center;
        font-weight: 600;
    }
    
    .subtitle {
        color: #0f766e;
        text-align: center;
        font-style: italic;
        margin-bottom: 1rem;
    }
    
    .webhook-status {
        background-color: #fef3c7;
        border-left: 4px solid #f59e0b;
        padding: 1rem;
        border-radius: 8px;
        margin: 1rem 0;
    }
    
    .analysis-result {
        background-color: #f0fdf4;
        border-left: 4px solid #22c55e;
        padding: 1rem;
        border-radius: 8px;
        margin: 1rem 0;
    }
    
    .error-result {
        background-color: #fef2f2;
        border-left: 4px solid #ef4444;
        padding: 1rem;
        border-radius: 8px;
        margin: 1rem 0;
    }
    
    .log-preview {
        background-color: #f3f4f6;
        padding: 1rem;
        border-radius: 8px;
        font-family: monospace;
        white-space: pre-wrap;
        max-height: 300px;
        overflow-y: auto;
        margin: 1rem 0;
    }
    
    .sidebar-header {
        color: #0f766e;
        margin-bottom: 1rem;
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

# Function to extract analysis ID from webhook prompt
def extract_analysis_id(prompt_text):
    """Extract analysis ID from webhook prompt"""
    patterns = [
        r"Analysis ID:\s*([a-zA-Z0-9-]+)",
        r"REQUEST #([a-zA-Z0-9-]+)",
        r"analysis request #([a-zA-Z0-9-]+)"
    ]
    
    for pattern in patterns:
        match = re.search(pattern, prompt_text, re.IGNORECASE)
        if match:
            return match.group(1)
    return None

# Function to store analysis result
def store_analysis_result(analysis_id, prompt, response_content, status="completed"):
    """Store analysis result in session state"""
    if analysis_id:
        st.session_state.analysis_results[analysis_id] = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "prompt": prompt,
            "response": response_content,
            "status": status,
            "log_preview": prompt[:500] if len(prompt) > 500 else prompt
        }

# Function to create webhook hash for duplicate detection
def get_webhook_hash(prompt):
    """Create a simple hash of the webhook prompt to detect duplicates"""
    import hashlib
    return hashlib.md5(prompt.encode()).hexdigest()[:8]

# Check for webhook prompt parameter
query_params = st.query_params
webhook_prompt = None
analysis_id = None
is_webhook_request = False

if "prompt" in query_params:
    try:
        webhook_prompt = urllib.parse.unquote_plus(query_params["prompt"])
        analysis_id = extract_analysis_id(webhook_prompt)
        is_webhook_request = True
        
        # Create webhook hash for duplicate detection
        webhook_hash = get_webhook_hash(webhook_prompt)
        
        st.markdown(f"""
        <div class="webhook-status">
            <strong>🔗 Webhook Request Received</strong><br>
            Analysis ID: <code>{analysis_id or 'Auto-generated'}</code><br>
            Processing log analysis request from Cribl Stream...<br>
            <small>Hash: {webhook_hash}</small>
        </div>
        """, unsafe_allow_html=True)
        
    except Exception as e:
        st.error(f"Error processing webhook prompt: {str(e)}")
        webhook_prompt = None

# Sidebar with enhanced options
with st.sidebar:
    st.markdown('<h3 class="sidebar-header">🎛 Model Settings</h3>', unsafe_allow_html=True)
    model_choice = st.selectbox(
        "Select Gemini Model:",
        ["gemini-1.5-flash", "gemini-1.5-pro", "gemini-1.0-pro"],
        index=0,
        help="gemini-1.5-flash is faster, gemini-1.5-pro is more capable"
    )
    
    # Get LLM instance
    llm = get_llm(model_choice)
    
    # Create conversation chain
    chat_chain = RunnableWithMessageHistory(
        prompt_template | llm,
        get_session_history=lambda session_id: st.session_state.chat_history,
        input_messages_key="input",
        history_messages_key="history"
    )
    
    st.markdown('<h3 class="sidebar-header">⚙ Options</h3>', unsafe_allow_html=True)
    if st.button("🗑 Clear Chat History", use_container_width=True):
        st.session_state.chat_history.clear()
        st.session_state.processed_webhooks.clear()
        st.rerun()
    
    if st.button("🧹 Clear Analysis Results", use_container_width=True):
        st.session_state.analysis_results.clear()
        st.rerun()
    
    # Webhook status
    st.markdown('<h3 class="sidebar-header">🔗 Webhook Status</h3>', unsafe_allow_html=True)
    if is_webhook_request:
        st.success("✅ Webhook request active")
        st.info(f"Analyzing {len(webhook_prompt)} characters")
        if analysis_id:
            st.code(f"ID: {analysis_id}")
        else:
            st.code(f"Hash: {get_webhook_hash(webhook_prompt) if webhook_prompt else 'N/A'}")
    else:
        st.info("⏳ Waiting for webhook requests")
    
    # Results summary
    if st.session_state.analysis_results:
        st.markdown('<h3 class="sidebar-header">📊 Analysis Results</h3>', unsafe_allow_html=True)
        st.info(f"Total analyses: {len(st.session_state.analysis_results)}")
        
        if st.button("📋 View All Results", use_container_width=True):
            st.session_state.show_results = True
    
    # Quick questions
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

# Show results view if requested
if hasattr(st.session_state, 'show_results') and st.session_state.show_results:
    st.markdown("## 📊 Analysis Results Dashboard")
    
    if st.button("← Back to Chat"):
        del st.session_state.show_results
        st.rerun()
    
    if st.session_state.analysis_results:
        # Sort results by timestamp (newest first)
        sorted_results = sorted(
            st.session_state.analysis_results.items(),
            key=lambda x: x[1]['timestamp'],
            reverse=True
        )
        
        for result_id, result in sorted_results:
            status_color = "🟢" if result['status'] == 'completed' else "🔴"
            
            with st.expander(f"{status_color} Analysis {result_id} - {result['timestamp']}"):
                col1, col2 = st.columns([3, 1])
                
                with col1:
                    st.markdown(f"*Status:* {result['status']}")
                    st.markdown("*Log Preview:*")
                    st.code(result.get('log_preview', 'N/A'), language="text")
                
                with col2:
                    st.download_button(
                        label="📥 Download",
                        data=json.dumps(result, indent=2),
                        file_name=f"analysis_{result_id}.json",
                        mime="application/json",
                        key=f"download_{result_id}"
                    )
                
                st.markdown("*Analysis Response:*")
                st.markdown(result['response'])
    else:
        st.info("No analysis results available yet.")

else:
    # Regular chat interface
    
    # Display chat messages
    for message in st.session_state.chat_history.messages:
        with st.chat_message(message.type):
            st.write(message.content)

    # Handle webhook prompt automatically
    if webhook_prompt:
        webhook_hash = get_webhook_hash(webhook_prompt)
        
        # Check if this webhook was already processed
        if webhook_hash not in st.session_state.processed_webhooks:
            st.session_state.processed_webhooks.add(webhook_hash)
            
            # If no analysis_id, generate one
            if not analysis_id:
                analysis_id = f"auto_{webhook_hash}"
            
            # Display webhook prompt as user message
            with st.chat_message("user"):
                st.write("🔗 *Webhook Log Analysis Request:*")
                if analysis_id:
                    st.write(f"*Analysis ID:* {analysis_id}")
                
                # Show log preview in a nice format
                st.markdown("*Log Data:*")
                st.markdown('<div class="log-preview">' + webhook_prompt + '</div>', unsafe_allow_html=True)
            
            # Generate and display bot response
            with st.chat_message("assistant"):
                with st.spinner("🔍 Performing predictive and prescriptive log analysis..."):
                    try:
                        response = chat_chain.invoke(
                            {"input": webhook_prompt},
                            config={"configurable": {"session_id": f"webhook_{analysis_id}"}}
                        )
                        st.write(response.content)
                        
                        # Store the result
                        store_analysis_result(analysis_id, webhook_prompt, response.content, "completed")
                        
                        # Show success message
                        st.markdown(f"""
                        <div class="analysis-result">
                            <strong>✅ Analysis Complete</strong><br>
                            Analysis ID: <code>{analysis_id}</code><br>
                            Results stored and available in the dashboard.
                        </div>
                        """, unsafe_allow_html=True)
                        
                    except Exception as e:
                        error_msg = str(e)
                        st.markdown(f"""
                        <div class="error-result">
                            <strong>❌ Analysis Error</strong><br>
                            {error_msg}
                        </div>
                        """, unsafe_allow_html=True)
                        
                        # Store error result
                        store_analysis_result(analysis_id, webhook_prompt, f"Error: {error_msg}", "error")
        else:
            st.info(f"🔄 This webhook request (Hash: {webhook_hash}) has already been processed. Check the results dashboard.")

    # Handle quick question selection
    elif hasattr(st.session_state, 'selected_question'):
        user_input = st.session_state.selected_question
        delattr(st.session_state, 'selected_question')
    else:
        user_input = None

    # Chat input
    if is_webhook_request:
        st.chat_input("Webhook request is being processed...", disabled=True)
    else:
        if prompt := st.chat_input("Ask about insider threats or paste logs for analysis..."):
            user_input = prompt

    # Process regular user input (non-webhook)
    if user_input and not is_webhook_request:
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
                    elif "api key" in error_msg.lower():
                        st.error("❌ API key issue. Please check your GEMINI_API_KEY in secrets.toml")
                    else:
                        st.error(f"Error generating response: {error_msg}")

    # Display welcome message for new users
    if len(st.session_state.chat_history.messages) == 0 and not is_webhook_request:
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
                <p><strong>Current Webhook URL:</strong> <code>https://criblchatbot-hswvo3hhkgngsfvmwty9ql.streamlit.app/?prompt=YOUR_LOG_DATA</code></p>
                <p><strong>Ask me a question, use quick questions, or send logs via webhook!</strong></p>
            </div>
        </div>
        """, unsafe_allow_html=True)
