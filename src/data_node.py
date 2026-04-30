import chromadb
from chromadb.utils import embedding_functions
from src.crypto_utils import CryptoNode
import uuid

class ComputeToDataNode:
    def __init__(self, crypto_node: CryptoNode):
        self.crypto_node = crypto_node
        # Initialize an in-memory Chroma client
        self.chroma_client = chromadb.Client()
        # Using default sentence-transformers model (all-MiniLM-L6-v2) for local embeddings
        self.embedding_fn = embedding_functions.DefaultEmbeddingFunction()
        
        # Create or get a collection for the documents
        self.collection = self.chroma_client.get_or_create_collection(
            name="secure_documents",
            embedding_function=self.embedding_fn
        )

    def _chunk_text(self, text: str, chunk_size: int = 500, overlap: int = 50):
        """Simple text chunker based on characters."""
        chunks = []
        start = 0
        while start < len(text):
            end = start + chunk_size
            chunks.append(text[start:end])
            start += chunk_size - overlap
        return chunks

    def ingest_document(self, document_text: str, source_name: str):
        """
        Chunks the document, cryptographically signs each chunk,
        and indexes it locally. Raw data remains only in this node.
        """
        chunks = self._chunk_text(document_text)
        
        for i, chunk in enumerate(chunks):
            # 1. Sign the chunk and record provenance
            metadata = {"source": source_name, "chunk_index": i}
            chunk_hash, signature = self.crypto_node.process_and_sign_chunk(chunk, metadata)
            
            # 2. Store in local Vector DB
            # We store the hash and signature in metadata so it can be retrieved
            chunk_id = str(uuid.uuid4())
            self.collection.add(
                documents=[chunk],
                metadatas=[{
                    "source": source_name, 
                    "chunk_hash": chunk_hash,
                    "signature": signature
                }],
                ids=[chunk_id]
            )
        
        return len(chunks)

    def retrieve_verifiable_context(self, query: str, n_results: int = 3):
        """
        Compute-to-Data execution: Searches local data based on the query.
        Returns the chunks along with their cryptographic proofs.
        """
        if self.collection.count() == 0:
            return [], self.crypto_node.get_public_key_pem()

        results = self.collection.query(
            query_texts=[query],
            n_results=n_results
        )
        
        retrieved_items = []
        if results['documents'] and len(results['documents']) > 0:
            docs = results['documents'][0]
            metadatas = results['metadatas'][0]
            
            for doc, meta in zip(docs, metadatas):
                retrieved_items.append({
                    "content": doc,
                    "source": meta["source"],
                    "chunk_hash": meta["chunk_hash"],
                    "signature": meta["signature"]
                })
                
        return retrieved_items, self.crypto_node.get_public_key_pem()
