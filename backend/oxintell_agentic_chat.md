# OxInteLL Agentic Security Chat Documentation

## Overview

The OxInteLL module now features an advanced agentic workflow for security-related inquiries, powered by Langchain and CrewAI. This system employs multiple specialized AI agents working together to analyze security questions, assess threats, and provide comprehensive recommendations.

## Architecture

The agentic security chat system uses a multi-tiered approach:

1. **Query Complexity Assessment**: Incoming queries are analyzed to determine complexity
2. **Processing Path Selection**:
   - Simple queries → Langchain for efficient processing
   - Complex queries → CrewAI workflow for in-depth analysis

3. **CrewAI Agent Collaboration**:
   - **Security Researcher**: Gathers comprehensive information
   - **Threat Analyst**: Evaluates risks and potential impacts
   - **Security Advisor**: Provides actionable recommendations

## Using the Security Chat API

### Endpoint

```
POST /api/oxintell/security-chat
```

### Request Body

```json
{
  "query": "Your security-related question here"
}
```

### Response

```json
{
  "query": "Your original query",
  "response": "Detailed security analysis with recommendations",
  "processing_type": "simple" or "agentic"
}
```

### Example Usage

#### Simple Query
```json
{
  "query": "What is GraphQL?"
}
```

#### Complex Query
```json
{
  "query": "How do I mitigate against Log4j vulnerabilities in my Java application?"
}
```

## Analytics and Monitoring

### Endpoint

```
GET /api/oxintell/security-chat-analytics
```

Provides analytics on query volume, complexity distribution, and popular topics.

### Health Check

```
GET /api/oxintell/security-chat-health
```

Monitors the status of the agentic security chat services.

## Benefits of the Agentic Approach

- **Adaptive Analysis**: Resources scaled based on query complexity
- **Specialized Expertise**: Different agents tackle different aspects of security
- **Comprehensive Responses**: Multi-perspective analysis with research, threat assessment, and practical advice
- **Improved Performance**: Faster responses for simpler queries
