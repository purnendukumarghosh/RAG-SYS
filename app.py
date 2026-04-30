import streamlit as st
import os
import requests
from bs4 import BeautifulSoup
import PyPDF2
from io import BytesIO
from src.crypto_utils import CryptoNode
from src.data_node import ComputeToDataNode
from src.verifier_node import VerifierNode
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

st.set_page_config(page_title="Verifiable RAG PoC", layout="wide")
st.title("Cryptographically Verifiable RAG")
st.markdown("A Tripartite Architecture for Decentralized Provenance, Compute-to-Data Privacy, and Automated Fact-Checking")

# --- App State Initialization ---
if 'crypto_node' not in st.session_state:
    st.session_state.crypto_node = CryptoNode()
    
if 'data_node' not in st.session_state:
    st.session_state.data_node = ComputeToDataNode(st.session_state.crypto_node)
    
if 'is_indexed' not in st.session_state:
    st.session_state.is_indexed = False

# --- Sidebar Configuration ---
with st.sidebar:
    st.header("Node Configuration")
    
    # API Key Input for Verifier
    api_key = st.text_input("Gemini API Key (for Verifier)", type="password", value=os.getenv("GEMINI_API_KEY", ""))
    if api_key:
        os.environ["GEMINI_API_KEY"] = api_key
        
    st.divider()
    
    st.header("Data Provider Node")
    st.markdown("Upload documents to the local secure enclave.")
    uploaded_file = st.file_uploader("Upload a document", type=["txt", "pdf"])
    
    if st.button("Index Document (Compute-to-Data)"):
        if not uploaded_file:
            st.error("Please upload a file first.")
        else:
            with st.spinner("Parsing, Chunking, Hashing, Signing, and Indexing locally..."):
                content = ""
                if uploaded_file.name.endswith(".pdf"):
                    pdf_reader = PyPDF2.PdfReader(BytesIO(uploaded_file.read()))
                    for page in pdf_reader.pages:
                        text = page.extract_text()
                        if text:
                            content += text + "\n"
                else:
                    content = uploaded_file.read().decode("utf-8")
                
                num_chunks = st.session_state.data_node.ingest_document(content, uploaded_file.name)
                st.session_state.is_indexed = True
                st.success(f"Indexed {num_chunks} chunks successfully from {uploaded_file.name}!")
                
    st.divider()
    st.header("Trusted Sites")
    trusted_url = st.text_input("Index a Trusted Website URL")
    if st.button("Index Site"):
        if not trusted_url:
            st.error("Please enter a URL first.")
        else:
            with st.spinner("Scraping, Chunking, Hashing, Signing, and Indexing locally..."):
                try:
                    response = requests.get(trusted_url, timeout=10)
                    response.raise_for_status()
                    soup = BeautifulSoup(response.content, 'html.parser')
                    # Extract text and remove excess whitespace
                    text = soup.get_text(separator=' ', strip=True)
                    num_chunks = st.session_state.data_node.ingest_document(text, trusted_url)
                    st.session_state.is_indexed = True
                    st.success(f"Indexed {num_chunks} chunks successfully from URL!")
                except Exception as e:
                    st.error(f"Failed to scrape URL: {e}")
                
    if st.session_state.is_indexed:
        st.info("Data Node Public Key (DID):")
        st.code(st.session_state.crypto_node.get_public_key_pem()[:100] + "...", language="text")

# --- Main Interaction Area ---
st.header("Verifier Node (Chatbot & RAG Client)")

if "messages" not in st.session_state:
    st.session_state.messages = []

# Display chat messages from history on app rerun
for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])
        if "fact_check" in message:
            if message["fact_check"].get("passed"):
                st.success("✅ Fact-Check Passed: " + message["fact_check"].get("explanation", ""))
            else:
                st.error("❌ Fact-Check Failed: " + message["fact_check"].get("explanation", ""))

# React to user input
if prompt := st.chat_input("Ask a question about the indexed documents or chat generally..."):
    # Display user message in chat message container
    st.chat_message("user").markdown(prompt)
    # Add user message to chat history
    st.session_state.messages.append({"role": "user", "content": prompt})

    if not api_key:
        st.warning("Please provide a Gemini API Key in the sidebar.")
        st.stop()

    # Initialize Verifier
    verifier = VerifierNode(api_key=api_key)
    
    with st.chat_message("assistant"):
        # 1. Retrieval
        retrieved_items = []
        dp_public_key = None
        if st.session_state.is_indexed:
            with st.status("Fetching Data...", expanded=False) as status:
                retrieved_items, dp_public_key = st.session_state.data_node.retrieve_verifiable_context(prompt)
                if not retrieved_items:
                    status.update(label="No Context Found", state="complete")
                else:
                    status.update(label=f"Retrieved {len(retrieved_items)} chunks", state="complete")
        
        # 2. Verification
        verified_chunks = []
        if retrieved_items:
            with st.status("Verifying Cryptographic Provenance...", expanded=False) as status:
                verified_chunks, verification_results = verifier.verify_context(retrieved_items, dp_public_key)
                if not verified_chunks:
                    status.update(label="Verification Failed", state="error")
                else:
                    status.update(label=f"{len(verified_chunks)} chunks passed verification", state="complete")
        
        # 3. Generation
        with st.spinner("Generating Answer..."):
            answer, context_text = verifier.generate_answer(prompt, verified_chunks)
            st.markdown(answer)
        
        # 4. Automated Fact-Checking
        fact_check_result = None
        if verified_chunks:
            with st.spinner("Auditing against verified evidence..."):
                fact_check_result = verifier.fact_check_answer(prompt, answer, context_text)
                if fact_check_result.get("passed"):
                    st.success("✅ **Fact-Check Passed**: " + fact_check_result.get("explanation", ""))
                else:
                    st.error("❌ **Fact-Check Failed**: " + fact_check_result.get("explanation", ""))
        
        # Add assistant response to chat history
        msg_data = {"role": "assistant", "content": answer}
        if fact_check_result:
            msg_data["fact_check"] = fact_check_result
        st.session_state.messages.append(msg_data)
