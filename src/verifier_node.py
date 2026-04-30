import google.generativeai as genai
import os
from src.crypto_utils import CryptoNode

class VerifierNode:
    def __init__(self, api_key: str):
        # Configure Gemini API
        genai.configure(api_key=api_key)
        # Dynamically find an available model
        self.model = None
        for m in genai.list_models():
            if "generateContent" in m.supported_generation_methods:
                # m.name is already in the format "models/gemini-..."
                self.model = genai.GenerativeModel(m.name.replace("models/", ""))
                break
        
        if self.model is None:
            raise Exception("No generative models found for the given API key.")
            
        # We need an instance just to access the verification logic (no keys needed for this part)
        self.crypto_verifier = CryptoNode()

    def verify_context(self, retrieved_items: list, public_key_pem: str):
        """
        Step 1: Cryptographically verify each retrieved chunk.
        Discards any chunk that fails signature verification.
        """
        verified_chunks = []
        verification_results = []

        for item in retrieved_items:
            content = item["content"]
            claimed_hash = item["chunk_hash"]
            signature = item["signature"]

            # 1. Re-hash the content to ensure it wasn't tampered with
            actual_hash = self.crypto_verifier.hash_content(content)
            
            # 2. Verify the hash matches the signature using the Data Provider's Public Key
            is_valid_sig = self.crypto_verifier.verify_signature(
                actual_hash, signature, public_key_pem
            )

            is_valid = (actual_hash == claimed_hash) and is_valid_sig
            
            verification_results.append({
                "content_preview": content[:100] + "...",
                "source": item["source"],
                "hash_matches": actual_hash == claimed_hash,
                "signature_valid": is_valid_sig,
                "overall_valid": is_valid
            })

            if is_valid:
                verified_chunks.append(item)

        return verified_chunks, verification_results

    def generate_answer(self, query: str, verified_chunks: list):
        """
        Step 2: Generate an answer using the verified context, or general knowledge if none exists.
        """
        if verified_chunks:
            context_text = "\n\n".join([f"Source: {c['source']}\n{c['content']}" for c in verified_chunks])
            
            prompt = f"""
You are a helpful general-purpose AI Chatbot. 
You have been provided with cryptographically verified context from the user's documents.

You can answer general questions using your general knowledge. However, if the user's question relates to the provided Context, you MUST incorporate that Context and ensure your answer does not contradict it.

Context:
{context_text}

Question:
{query}

Answer:
"""
        else:
            context_text = ""
            prompt = f"""
You are a helpful AI assistant. The user has asked a question, but no specific verified context was found in their documents for this query.
Please answer the user's question using your general knowledge, and be conversational.

Question:
{query}

Answer:
"""
        
        response = self.model.generate_content(prompt)
        return response.text, context_text

    def fact_check_answer(self, query: str, generated_answer: str, context_text: str):
        """
        Step 3: Automated Fact-Checking.
        An independent agent call that audits the generated answer against the verified context.
        """
        if not context_text:
             return {"passed": True, "explanation": "No verified context was needed; the AI answered using general knowledge."}

        prompt = f"""
You are a strict Fact-Checking Auditor. The AI was asked a question and generated an answer. The AI is a general-purpose chatbot but was also given Verified Evidence Context.

Your job is to check if the Generated Answer contains any claims about the topics in the Verified Evidence Context that contradict or hallucinate beyond what is stated in the Context.
It is OKAY if the AI includes general conversational knowledge, as long as it doesn't invent false facts about the specific entities or events mentioned in the Verified Evidence Context.

Verified Evidence Context:
{context_text}

User Question:
{query}

Generated Answer:
{generated_answer}

Respond in JSON format with two keys:
- "passed": boolean (true if claims related to the context are supported, false if it contains unsupported claims or contradicts the context)
- "explanation": A brief explanation of your decision.

JSON Response:
"""
        # Tell the model to output JSON
        response = self.model.generate_content(
            prompt,
            generation_config=genai.types.GenerationConfig(
                response_mime_type="application/json"
            )
        )
        
        import json
        try:
            result = json.loads(response.text)
            return result
        except Exception as e:
            return {"passed": False, "explanation": f"Failed to parse auditor response: {str(e)}"}
