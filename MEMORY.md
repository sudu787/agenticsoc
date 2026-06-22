# SecureFlow AI — Memory System

## Memory Types

| Type | Storage | Retrieval | Purpose |
|---|---|---|---|
| **Working Memory** | In-process dict | O(1) lookup | Current investigation context |
| **Episodic Memory** | SQLite + embeddings | Cosine similarity | Past incident recall |
| **Organizational Memory** | Database + graph | Graph + keyword | Cross-team knowledge base |
| **Threat Memory** | Knowledge Graph | Graph traversal | Threat actor TTP patterns |

## Episodic Memory Retrieval