"""AWS Bedrock AgentCore Gateway adapter.

Implements the REQUEST interceptor pattern: parses MCP gateway events,
runs detection, and returns transformedGatewayRequest (passthrough) or
transformedGatewayResponse (block + 403).
"""
