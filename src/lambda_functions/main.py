import json
import boto3
from sentence_transformers import SentenceTransformer
import pinecone
import os
from urllib.parse import unquote_plus

# Initialize clients outside the handler for reuse
s3 = boto3.client('s3')
model = None
pinecone_index = None

def initialize_components():
    global model, pinecone_index
    
    # Load the embedding model (cache this for performance)
    if model is None:
        model = SentenceTransformer('all-MiniLM-L6-v2')
    
    # Initialize Pinecone
    if pinecone_index is None:
        pinecone.init(
            api_key=os.environ['PINECONE_API_KEY'],
            environment=os.environ['PINECONE_ENV']
        )
        index_name = os.environ['PINECONE_INDEX_NAME']
        pinecone_index = pinecone.Index(index_name)

def lambda_handler(event, context):
    try:
        # Initialize model and Pinecone
        initialize_components()
        
        # Parse the S3 event
        bucket = event['Records'][0]['s3']['bucket']['name']
        key = unquote_plus(event['Records'][0]['s3']['object']['key'])
        
        # Get the document from S3
        response = s3.get_object(Bucket=bucket, Key=key)
        document_content = response['Body'].read().decode('utf-8')
        
        # Split document into chunks (simple approach - consider better chunking for your use case)
        chunks = [document_content[i:i+1000] for i in range(0, len(document_content), 1000)]
        
        # Generate embeddings for each chunk
        embeddings = model.encode(chunks)
        
        # Prepare vectors for Pinecone
        vectors = []
        for i, (chunk, embedding) in enumerate(zip(chunks, embeddings)):
            vector_id = f"{key}-chunk-{i}"
            vectors.append((vector_id, embedding.tolist(), {"text": chunk, "source": key}))
        
        # Upsert vectors into Pinecone
        pinecone_index.upsert(vectors=vectors)
        
        return {
            'statusCode': 200,
            'body': json.dumps(f"Successfully processed {key} and stored {len(vectors)} embeddings")
        }
        
    except Exception as e:
        print(f"Error: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps(f"Error processing document: {str(e)}")
        }