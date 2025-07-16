import boto3
import json
import os
from sentence_transformers import SentenceTransformer
import pinecone

# Initialize clients
bedrock = boto3.client(service_name='bedrock-runtime', region_name='us-west-2')
model = SentenceTransformer('all-MiniLM-L6-v2')  # Same as indexing model

# Pinecone setup
pinecone.init(
    api_key=os.environ['PINECONE_API_KEY'],
    environment=os.environ['PINECONE_ENV']
)
index = pinecone.Index(os.environ['PINECONE_INDEX_NAME'])

def query_with_context(query, top_k=3):
    """Query Pinecone and generate answer with Bedrock"""
    
    # 1. Generate embedding for the query
    query_embedding = model.encode(query).tolist()
    
    # 2. Query Pinecone for similar vectors
    results = index.query(
        vector=query_embedding,
        top_k=top_k,
        include_metadata=True
    )
    
    # 3. Prepare context from matches
    context = "\n\n".join([match.metadata['text'] for match in results.matches])
    
    # 4. Generate answer using Bedrock (Claude model example)
    prompt = f"""Human: You are a helpful AI assistant. Answer the question based on the following context.
    
    Context:
    {context}
    
    Question: {query}
    
    Assistant:"""
    
    body = json.dumps({
        "prompt": prompt,
        "max_tokens_to_sample": 1000,
        "temperature": 0.5,
        "top_p": 0.9,
    })
    
    response = bedrock.invoke_model(
        body=body,
        modelId="anthropic.claude-v2",
        accept="application/json",
        contentType="application/json"
    )
    
    response_body = json.loads(response.get('body').read())
    return response_body.get('completion')

# Example usage
if __name__ == "__main__":
    question = "What are the key security recommendations in the document?"
    answer = query_with_context(question)
    print(f"Question: {question}")
    print(f"Answer: {answer}")