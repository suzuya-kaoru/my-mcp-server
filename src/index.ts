import { McpAgent } from 'agents/mcp';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

// OAuth configuration
const OAUTH_CONFIG = {
  authServerUrl: 'http://localhost:8080',
  clientId: 'sanctum-test-client',
  clientSecret: 'sanctum-test-secret',
  redirectUri: 'http://localhost:8787/oauth/callback', // Development URL
};

// OAuth helper functions
class OAuthService {
  static generateAuthUrl(state?: string): string {
    const params = new URLSearchParams({
      client_id: OAUTH_CONFIG.clientId,
      redirect_uri: OAUTH_CONFIG.redirectUri,
      response_type: 'code',
      state: state || Math.random().toString(36).substring(7),
    });
    return `${OAUTH_CONFIG.authServerUrl}/oauth/authorize?${params.toString()}`;
  }

  static async exchangeCodeForToken(
    code: string,
    state?: string
  ): Promise<any> {
    const response = await fetch(
      `${OAUTH_CONFIG.authServerUrl}/api/oauth/token`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Accept: 'application/json',
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          client_id: OAUTH_CONFIG.clientId,
          client_secret: OAUTH_CONFIG.clientSecret,
          code: code,
          redirect_uri: OAUTH_CONFIG.redirectUri,
        }),
      }
    );

    if (!response.ok) {
      throw new Error(`Token exchange failed: ${response.status}`);
    }

    return await response.json();
  }

  static async verifyToken(token: string): Promise<any> {
    const response = await fetch(`${OAUTH_CONFIG.authServerUrl}/api/user`, {
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: 'application/json',
      },
    });

    if (!response.ok) {
      throw new Error(`Token verification failed: ${response.status}`);
    }

    return await response.json();
  }
}

// Token management for MCP tools
class TokenManager {
  private static cachedToken: string | null = null;

  static setToken(token: string) {
    this.cachedToken = token;
  }

  static getToken(): string | null {
    // Priority order: cached token > environment variable > URL parameter
    if (this.cachedToken) return this.cachedToken;

    // Check environment variable (for MCP client configuration)
    if (typeof process !== 'undefined' && process.env?.OAUTH_TOKEN) {
      return process.env.OAUTH_TOKEN;
    }

    // Check URL parameter (for remote MCP servers)
    if (typeof window !== 'undefined' && window.location) {
      const urlParams = new URLSearchParams(window.location.search);
      const urlToken = urlParams.get('token') || urlParams.get('auth');
      if (urlToken) return urlToken;
    }

    return null;
  }

  static clearToken() {
    this.cachedToken = null;
  }
}

// Define our MCP agent with tools
export class MyMCP extends McpAgent {
  server = new McpServer({
    name: 'OAuth-Protected Calculator',
    version: '1.0.0',
  });

  async init() {
    // Protected addition tool with authentication
    this.server.tool(
      'add',
      { a: z.number(), b: z.number() },
      async ({ a, b }) => {
        // Check for authentication token
        const token = TokenManager.getToken();

        if (!token) {
          return {
            content: [
              {
                type: 'text',
                text: 'Error: Authentication required. Please provide a valid OAuth token.',
              },
            ],
          };
        }

        // Verify the token
        try {
          await OAuthService.verifyToken(token);
        } catch (error) {
          return {
            content: [
              {
                type: 'text',
                text: `Error: Invalid authentication token. ${
                  error instanceof Error
                    ? error.message
                    : 'Authentication failed'
                }`,
              },
            ],
          };
        }

        // If authentication is successful, perform the addition
        return {
          content: [{ type: 'text', text: String(a + b) }],
        };
      }
    );

    // Calculator tool with multiple operations
    this.server.tool(
      'calculate',
      {
        operation: z.enum(['add', 'subtract', 'multiply', 'divide']),
        a: z.number(),
        b: z.number(),
      },
      async ({ operation, a, b }) => {
        let result: number;
        switch (operation) {
          case 'add':
            result = a + b;
            break;
          case 'subtract':
            result = a - b;
            break;
          case 'multiply':
            result = a * b;
            break;
          case 'divide':
            if (b === 0)
              return {
                content: [
                  {
                    type: 'text',
                    text: 'Error: Cannot divide by zero',
                  },
                ],
              };
            result = a / b;
            break;
        }
        return { content: [{ type: 'text', text: String(result) }] };
      }
    );
  }
}

export default {
  fetch(request: Request, env: Env, ctx: ExecutionContext) {
    const url = new URL(request.url);

    // Extract authentication from URL parameters or headers
    const urlToken =
      url.searchParams.get('token') || url.searchParams.get('auth');
    const headerToken =
      request.headers.get('X-MCP-Auth') ||
      (request.headers.get('Authorization')?.startsWith('Bearer ')
        ? request.headers.get('Authorization')?.substring(7)
        : null);

    // Set token for this request if available
    if (urlToken || headerToken) {
      TokenManager.setToken(urlToken || headerToken || '');
    }

    // OAuth endpoints
    if (url.pathname === '/oauth/login') {
      return handleOAuthLogin(request);
    }

    if (url.pathname === '/oauth/callback') {
      return handleOAuthCallback(request);
    }

    // Protected API endpoint
    if (url.pathname === '/api/protected') {
      return handleProtectedAPI(request);
    }

    // MCP endpoints
    if (url.pathname === '/sse' || url.pathname === '/sse/message') {
      return MyMCP.serveSSE('/sse').fetch(request, env, ctx);
    }

    if (url.pathname === '/mcp') {
      return MyMCP.serve('/mcp').fetch(request, env, ctx);
    }

    // Default homepage with OAuth links
    if (url.pathname === '/') {
      return handleHomepage(request);
    }

    return new Response('Not found', { status: 404 });
  },
};

// OAuth endpoint handlers
async function handleOAuthLogin(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const state =
    url.searchParams.get('state') || Math.random().toString(36).substring(7);

  const authUrl = OAuthService.generateAuthUrl(state);

  return new Response(
    JSON.stringify({
      auth_url: authUrl,
      state: state,
      message: 'Visit the auth_url to authenticate',
    }),
    {
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
      },
    }
  );
}

async function handleOAuthCallback(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');

  if (!code) {
    return new Response('Missing authorization code', { status: 400 });
  }

  try {
    const tokenData = await OAuthService.exchangeCodeForToken(
      code,
      state || undefined
    );
    const user = await OAuthService.verifyToken(tokenData.access_token);

    return new Response(
      `
      <!DOCTYPE html>
      <html>
        <head>
          <title>OAuth Success</title>
          <style>
            body { font-family: Arial, sans-serif; margin: 40px; }
            .success { color: green; }
            .token { background: #f4f4f4; padding: 10px; border-radius: 5px; word-break: break-all; }
          </style>
        </head>
        <body>
          <h1 class="success">🎉 OAuth Authentication Successful!</h1>
          <p><strong>User:</strong> ${user.name} (${user.email})</p>
          <p><strong>Access Token:</strong></p>
          <div class="token">${tokenData.access_token}</div>
          <p>You can now use this token to access protected MCP tools!</p>
          <ul>
            <li><code>advanced_calculate</code> - Advanced math operations</li>
            <li><code>get_user_info</code> - Get your user information</li>
          </ul>
        </body>
      </html>
    `,
      {
        headers: { 'Content-Type': 'text/html' },
      }
    );
  } catch (error) {
    return new Response(
      `OAuth callback failed: ${
        error instanceof Error ? error.message : String(error)
      }`,
      { status: 400 }
    );
  }
}

async function handleProtectedAPI(request: Request): Promise<Response> {
  const authHeader = request.headers.get('Authorization');

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return new Response('Missing or invalid Authorization header', {
      status: 401,
    });
  }

  const token = authHeader.substring(7);

  try {
    const user = await OAuthService.verifyToken(token);
    return new Response(
      JSON.stringify({
        message: 'Access granted to protected resource',
        user: user,
        timestamp: new Date().toISOString(),
      }),
      {
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
        },
      }
    );
  } catch (error) {
    return new Response(
      `Token verification failed: ${
        error instanceof Error ? error.message : String(error)
      }`,
      { status: 401 }
    );
  }
}

async function handleHomepage(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const baseUrl = `${url.protocol}//${url.host}`;

  return new Response(
    `
    <!DOCTYPE html>
    <html>
      <head>
        <title>OAuth-Protected MCP Server</title>
        <style>
          body { font-family: Arial, sans-serif; margin: 40px; }
          .section { margin: 20px 0; padding: 20px; border: 1px solid #ddd; border-radius: 5px; }
          button { padding: 10px 20px; margin: 10px 0; }
          pre { background: #f4f4f4; padding: 10px; border-radius: 5px; }
        </style>
      </head>
      <body>
        <h1>🔐 OAuth-Protected MCP Server</h1>
        
        <div class="section">
          <h2>Public Tools</h2>
          <p>These tools work without authentication:</p>
          <ul>
            <li><code>calculate</code> - Basic calculator operations</li>
          </ul>
        </div>

        <div class="section">
          <h2>Protected Tools</h2>
          <p>These tools require OAuth authentication:</p>
          <ul>
            <li><code>add</code> - Simple addition (requires authentication)</li>
            <li><code>advanced_calculate</code> - Advanced math operations (power, sqrt, log, factorial)</li>
            <li><code>get_user_info</code> - Get authenticated user information</li>
          </ul>
        </div>

        <div class="section">
          <h2>OAuth Authentication</h2>
          <p>To access protected tools, you need to authenticate:</p>
          <ol>
            <li>Click "Start OAuth" to get authentication URL</li>
            <li>Visit the authentication URL and login with: <code>test@example.com</code> / <code>password123</code></li>
            <li>Copy the access token from the callback page</li>
            <li>Use the token with protected MCP tools</li>
          </ol>
          <button onclick="startOAuth()">Start OAuth</button>
          <pre id="authResult"></pre>
        </div>

        <div class="section">
          <h2>API Endpoints</h2>
          <ul>
            <li><code>GET /</code> - This page</li>
            <li><code>GET /oauth/login</code> - Get OAuth authentication URL</li>
            <li><code>GET /oauth/callback</code> - OAuth callback handler</li>
            <li><code>GET /api/protected</code> - Protected API endpoint (requires Bearer token)</li>
            <li><code>POST /mcp</code> - MCP protocol endpoint</li>
          </ul>
        </div>

        <script>
          async function startOAuth() {
            try {
              const response = await fetch('${baseUrl}/oauth/login');
              const data = await response.json();
              document.getElementById('authResult').textContent = 
                'Authentication URL: ' + data.auth_url + '\\n\\nState: ' + data.state;
              
              // Open auth URL in new tab
              window.open(data.auth_url, '_blank');
            } catch (error) {
              document.getElementById('authResult').textContent = 'Error: ' + error.message;
            }
          }
        </script>
      </body>
    </html>
  `,
    {
      headers: { 'Content-Type': 'text/html' },
    }
  );
}
