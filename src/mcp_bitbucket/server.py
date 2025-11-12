import asyncio
import os
import base64
import re
from datetime import datetime, timedelta, timezone
from mcp.server.models import InitializationOptions
import mcp.types as types
from mcp.server import NotificationOptions, Server
import mcp.server.stdio
import requests
from requests.auth import HTTPBasicAuth
import json

# Prefer OS trust store (macOS Keychain) for TLS if available
try:
    import truststore  # type: ignore
    truststore.inject_into_ssl()
except Exception:
    pass

# Initialize server
server = Server("bitbucket-api")

# Environment variables for Bitbucket authentication and deployment mode
BITBUCKET_USERNAME = os.getenv("BITBUCKET_USERNAME")
BITBUCKET_APP_PASSWORD = os.getenv("BITBUCKET_APP_PASSWORD")
BITBUCKET_TOKEN = os.getenv("BITBUCKET_TOKEN")  # For Bitbucket Server/DC PATs
BITBUCKET_BASE_URL = os.getenv("BITBUCKET_BASE_URL")  # e.g., https://stash.veritas.com
BITBUCKET_MODE = (os.getenv("BITBUCKET_MODE") or "cloud").strip().lower()  # cloud|server|dc

def is_server_mode() -> bool:
    """Return True if configured to talk to Bitbucket Server/Data Center."""
    return bool(BITBUCKET_BASE_URL) or BITBUCKET_MODE in ("server", "dc", "datacenter")

if not all([BITBUCKET_USERNAME, BITBUCKET_APP_PASSWORD]) and not BITBUCKET_TOKEN:
    raise ValueError(
        "Missing credentials: set BITBUCKET_TOKEN (preferred for Server/DC) "
        "or BITBUCKET_USERNAME and BITBUCKET_APP_PASSWORD"
    )

# TLS verification configuration to support corporate CA bundles and overrides
verify_env = os.getenv("BITBUCKET_VERIFY_SSL")
if verify_env is not None:
    # Explicit override via env var
    VERIFY = verify_env.strip().lower() not in ("0", "false", "no")
else:
    # Fall back to path-based verification if provided
    VERIFY_PATH = (
        os.getenv("REQUESTS_CA_BUNDLE")
        or os.getenv("SSL_CERT_FILE")
        or os.getenv("CURL_CA_BUNDLE")
    )
    VERIFY = VERIFY_PATH if VERIFY_PATH else True

def format_permission_error(response_text):
    """Format permission errors into user-friendly messages."""
    try:
        error_data = json.loads(response_text)
        if "error" in error_data:
            required = error_data["error"].get("detail", {}).get("required", [])
            granted = error_data["error"].get("detail", {}).get("granted", [])
            
            message = [
                "Permission Error:",
                f"Required permissions: {', '.join(required)}",
                f"Granted permissions: {', '.join(granted)}",
                "\nTo fix this:",
                "1. Go to Bitbucket Settings > App passwords",
                "2. Create a new app password with the required permissions",
                "3. Update your BITBUCKET_APP_PASSWORD environment variable"
            ]
            return "\n".join(message)
    except:
        pass
    return response_text

@server.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    """List available tools for Bitbucket integration."""
    return [
        # types.Tool(
        #     name="bb_create_repository",
        #     description="Create a new repository in Bitbucket",
        #     inputSchema={
        #         "type": "object",
        #         "properties": {
        #             "project_key": {
        #                 "type": "string",
        #                 "description": "The project key where the repository will be created (optional for personal repos)"
        #             },
        #             "name": {
        #                 "type": "string",
        #                 "description": "Repository name"
        #             },
        #             "description": {
        #                 "type": "string",
        #                 "description": "Repository description"
        #             },
        #             "is_private": {
        #                 "type": "boolean",
        #                 "description": "Whether the repository should be private",
        #                 "default": True
        #             },
        #             "workspace": {
        #                 "type": "string",
        #                 "description": "Target workspace (defaults to kallows, can use ~ for personal workspace)",
        #                 "default": "kallows"
        #             }
        #         },
        #         "required": ["name"]
        #     }
        # ),



        types.Tool(
            name="bb_create_repository",
            description="Create a new repository in Bitbucket",
            inputSchema={
                "type": "object",
                "properties": {
                    "project_key": {
                        "type": "string",
                        "description": "The project key where the repository will be created (optional for personal repos)"
                    },
                    "name": {
                        "type": "string",
                        "description": "Repository name"
                    },
                    "description": {
                        "type": "string",
                        "description": "Repository description"
                    },
                    "is_private": {
                        "type": "boolean",
                        "description": "Whether the repository should be private",
                        "default": True
                    },
                    "has_issues": {
                        "type": "boolean",
                        "description": "Whether to initialize the repository with issue tracking enabled",
                        "default": True
                    },
                    "workspace": {
                        "type": "string",
                        "description": "Target workspace (defaults to kallows, can use ~ for personal workspace)",
                        "default": "kallows"
                    }
                },
                "required": ["name"]
            }
        ),
        types.Tool(
            name="bb_create_branch",
            description="Create a new branch in a Bitbucket repository",
            inputSchema={
                "type": "object", 
                "properties": {
                    "project_key": {
                        "type": "string",
                        "description": "Project key (required for Bitbucket Server/DC)"
                    },
                    "workspace": {
                        "type": "string",
                        "description": "Repository workspace (defaults to kallows)",
                        "default": "kallows"
                    },
                    "repo_slug": {
                        "type": "string",
                        "description": "Repository slug/name"
                    },
                    "branch": {
                        "type": "string",
                        "description": "Name for the new branch"
                    },
                    "start_point": {
                        "type": "string", 
                        "description": "Branch/commit to create from (defaults to main)",
                        "default": "main"
                    }
                },
                "required": ["repo_slug", "branch"]
            }
        ),        
        types.Tool(
            name="bb_delete_repository",
            description="Delete a repository from Bitbucket", # TODO: only works with delete repo priv, see if app password can get delete repo privilege
            inputSchema={
                "type": "object",
                "properties": {
                    "repo_slug": {
                        "type": "string",
                        "description": "The repository slug to delete"
                    },
                    "workspace": {
                        "type": "string",
                        "description": "Target workspace (defaults to kallows, can use ~ for personal workspace)",
                        "default": "kallows"
                    }
                },
                "required": ["repo_slug"]
            }
        ),
        types.Tool(
            name="bb_read_file",
            description="Read a file from a Bitbucket repository",
            inputSchema={
                "type": "object",
                "properties": {
                    "workspace": {
                        "type": "string",
                        "description": "Repository workspace (defaults to kallows)",
                        "default": "kallows"
                    },
                    "repo_slug": {
                        "type": "string",
                        "description": "Repository slug/name"
                    },
                    "path": {
                        "type": "string",
                        "description": "Path to the file in the repository"
                    },
                    "branch": {
                        "type": "string",
                        "description": "Branch name (defaults to main/master)",
                        "default": "main"
                    },
                    "project_key": {
                        "type": "string",
                        "description": "Project key (required for Bitbucket Server/DC, will be auto-detected if not provided)"
                    }
                },
                "required": ["repo_slug", "path"]
            }
        ),
        types.Tool(
            name="bb_write_file",
            description="Write/update a file in a Bitbucket repository",
            inputSchema={
                "type": "object",
                "properties": {
                    "workspace": {
                        "type": "string",
                        "description": "Repository workspace (defaults to kallows)",
                        "default": "kallows"
                    },
                    "repo_slug": {
                        "type": "string",
                        "description": "Repository slug/name"
                    },
                    "path": {
                        "type": "string",
                        "description": "Path where to create/update the file"
                    },
                    "content": {
                        "type": "string",
                        "description": "Content to write to the file"
                    },
                    "message": {
                        "type": "string",
                        "description": "Commit message",
                        "default": "Update file via MCP"
                    },
                    "branch": {
                        "type": "string",
                        "description": "Branch name (defaults to main/master)",
                        "default": "main"
                    }
                },
                "required": ["repo_slug", "path", "content"]
            }
        ),
        types.Tool(
            name="bb_create_issue",
            description="Create an issue in a Bitbucket repository",
            inputSchema={
                "type": "object",
                "properties": {
                    "workspace": {
                        "type": "string",
                        "description": "Repository workspace (defaults to kallows)",
                        "default": "kallows"
                    },
                    "repo_slug": {
                        "type": "string",
                        "description": "Repository slug/name"
                    },
                    "title": {
                        "type": "string",
                        "description": "Issue title"
                    },
                    "content": {
                        "type": "string",
                        "description": "Issue content/description"
                    },
                    "kind": {
                        "type": "string",
                        "description": "Issue type (bug, enhancement, proposal, task)",
                        "default": "task"
                    },
                    "priority": {
                        "type": "string",
                        "description": "Issue priority (trivial, minor, major, critical, blocker)",
                        "default": "minor"
                    }
                },
                "required": ["repo_slug", "title", "content"]
            }
        ),
        types.Tool(
            name="bb_delete_issue",
            description="Delete an issue from a Bitbucket repository",
            inputSchema={
                "type": "object",
                "properties": {
                    "workspace": {
                        "type": "string",
                        "description": "Repository workspace (defaults to kallows)",
                        "default": "kallows"
                    },
                    "repo_slug": {
                        "type": "string",
                        "description": "Repository slug/name"
                    },
                    "issue_id": {
                        "type": "string",
                        "description": "ID of the issue to delete"
                    }
                },
                "required": ["repo_slug", "issue_id"]
            }
        ),
        types.Tool(
            name="bb_search_repositories",
            description="Search repositories in Bitbucket using Bitbucket's query syntax. Search by name (name ~ \"pattern\"), project key (project.key = \"PROJ\"), language (language = \"python\"), or dates (updated_on >= \"2024-01-19\"). NOTE: All dates must be in ISO 8601 format (YYYY-MM-DD). For searching files within repositories, use Bitbucket's code search in the web interface.",
            inputSchema={
                "type": "object",
                "properties": {
                    "workspace": {
                        "type": "string",
                        "description": "Workspace to search in (defaults to kallows)",
                        "default": "kallows"
                    },
                    "query": {
                        "type": "string",
                        "description": "Search query (e.g., 'name ~ \"test\"' or 'project.key = \"PROJ\"')"
                    },
                    "page": {
                        "type": "integer",
                        "description": "Page number for pagination",
                        "default": 1
                    },
                    "pagelen": {
                        "type": "integer",
                        "description": "Number of results per page (max 100)",
                        "default": 10
                    }
                },
                "required": ["query"]
            }
        ),
        types.Tool(
            name="bb_delete_file",
            description="Delete a file from a Bitbucket repository",
            inputSchema={
                "type": "object",
                "properties": {
                    "workspace": {
                        "type": "string",
                        "description": "Repository workspace (defaults to kallows)",
                        "default": "kallows"
                    },
                    "repo_slug": {
                        "type": "string",
                        "description": "Repository slug/name"
                    },
                    "path": {
                        "type": "string",
                        "description": "Path to the file to delete"
                    },
                    "message": {
                        "type": "string",
                        "description": "Commit message for the deletion",
                        "default": "Delete file via MCP"
                    },
                    "branch": {
                        "type": "string",
                        "description": "Branch name (defaults to main/master)",
                        "default": "main"
                    }
                },
                "required": ["repo_slug", "path"]
            }
        ),
        types.Tool(
            name="bb_create_pull_request",
            description="Create a new pull request in a Bitbucket repository",
            inputSchema={
                "type": "object",
                "properties": {
                    "workspace": {
                        "type": "string",
                        "description": "Repository workspace (defaults to kallows)",
                        "default": "kallows"
                    },
                    "repo_slug": {
                        "type": "string",
                        "description": "Repository slug/name"
                    },
                    "title": {
                        "type": "string",
                        "description": "Pull request title"
                    },
                    "description": {
                        "type": "string",
                        "description": "Pull request description"
                    },
                    "source_branch": {
                        "type": "string",
                        "description": "Branch containing your changes"
                    },
                    "destination_branch": {
                        "type": "string",
                        "description": "Branch you want to merge into",
                        "default": "main"
                    },
                    "close_source_branch": {
                        "type": "boolean",
                        "description": "Close source branch after merge",
                        "default": True
                    }
                },
                "required": ["repo_slug", "title", "source_branch"]
            }
        ),
        types.Tool(
            name="bb_list_repositories_created_by_user",
            description="List repositories likely created by a specific user in the last N months (Bitbucket Server/DC). Approximates creation by the earliest commit on the default branch.",
            inputSchema={
                "type": "object",
                "properties": {
                    "project_key": {
                        "type": "string",
                        "description": "Project key, e.g., VSAASP"
                    },
                    "author": {
                        "type": "string",
                        "description": "Bitbucket username/email substring (defaults to BITBUCKET_USERNAME)"
                    },
                    "months": {
                        "type": "integer",
                        "description": "Lookback window in months",
                        "default": 3
                    },
                    "pagelen": {
                        "type": "integer",
                        "description": "Batch size when scanning repos (max 100)",
                        "default": 50
                    }
                },
                "required": ["project_key"]
            }
        ),
        types.Tool(
            name="bb_list_branches_created_by_user",
            description="List branches created by a specific user within the last N months (Bitbucket Server/DC). Uses earliest unique commit on branch vs default branch as a proxy for creation.",
            inputSchema={
                "type": "object",
                "properties": {
                    "project_key": {
                        "type": "string",
                        "description": "Project key, e.g., VSAASP"
                    },
                    "repo_slug": {
                        "type": "string",
                        "description": "Repository slug/name, e.g., alta-copilot-framework"
                    },
                    "author": {
                        "type": "string",
                        "description": "Bitbucket username to filter by (defaults to BITBUCKET_USERNAME)"
                    },
                    "months": {
                        "type": "integer",
                        "description": "Lookback window in months",
                        "default": 3
                    }
                },
                "required": ["project_key", "repo_slug"]
            }
        )                
    ]

@server.call_tool()
async def handle_call_tool(name: str, arguments: dict | None) -> list[types.TextContent]:
    """Handle tool execution requests for Bitbucket operations."""
    try:
        # Ensure arguments is always a dict to avoid attribute errors
        if arguments is None:
            arguments = {}

        # Build auth and headers for Cloud (Basic) or Server/DC (Bearer or Basic)
        auth = None
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        if BITBUCKET_TOKEN:
            headers['Authorization'] = f'Bearer {BITBUCKET_TOKEN}'
        else:
            auth = HTTPBasicAuth(BITBUCKET_USERNAME, BITBUCKET_APP_PASSWORD)

        # if name == "bb_create_repository":
        #     workspace = arguments.get("workspace", "kallows")
        #     if workspace == "~":  # Personal workspace
        #         # First get the user's workspace
        #         user_url = "https://api.bitbucket.org/2.0/user"
        #         user_response = requests.get(user_url, auth=auth, headers=headers)
        #         if user_response.status_code != 200:
        #             return [types.TextContent(
        #                 type="text",
        #                 text=f"Failed to get user info: {user_response.status_code} - {format_permission_error(user_response.text)}",
        #                 isError=True
        #             )]
        #         workspace = user_response.json().get('username')
        #     repo_name = arguments.get("name")
        #     description = arguments.get("description", "")
        #     is_private = arguments.get("is_private", True)
        #     project_key = arguments.get("project_key")
        #     # Create repository payload
        #     payload = {
        #         "scm": "git",
        #         "name": repo_name,
        #         "is_private": is_private,
        #         "description": description
        #     }
        #     # Only add project if specified (required for workspace repos, not for personal)
        #     if project_key:
        #         payload["project"] = {"key": project_key}
        #     url = f"https://api.bitbucket.org/2.0/repositories/{workspace}/{repo_name.lower()}"
        #     response = requests.post(url, json=payload, auth=auth, headers=headers)
        #     if response.status_code in (200, 201):
        #         repo_url = response.json().get('links', {}).get('html', {}).get('href', '')
        #         return [types.TextContent(
        #             type="text",
        #             text=f"Repository created successfully in workspace '{workspace}'\nURL: {repo_url}"
        #         )]
        #     else:
        #         error_msg = format_permission_error(response.text)
        #         if workspace == "kallows" and "permission" in error_msg.lower():
        #             error_msg += "\n\nTip: You can try creating the repository in your personal workspace by setting workspace='~'"
        #         return [types.TextContent(
        #             type="text",
        #             text=f"Failed to create repository: {response.status_code}\n{error_msg}",
        #             isError=True
        #         )]


        if name == "bb_create_repository":
            workspace = arguments.get("workspace", "kallows")
            if workspace == "~":  # Personal workspace
                # First get the user's workspace
                user_url = "https://api.bitbucket.org/2.0/user"
                user_response = requests.get(user_url, auth=auth, headers=headers, verify=VERIFY)
                if user_response.status_code != 200:
                    return [types.TextContent(
                        type="text",
                        text=f"Failed to get user info: {user_response.status_code} - {format_permission_error(user_response.text)}",
                        isError=True
                    )]
                workspace = user_response.json().get('username')

            repo_name = arguments.get("name")
            description = arguments.get("description", "")
            is_private = arguments.get("is_private", True)
            project_key = arguments.get("project_key")

            # Create repository payload
            payload = {
                "scm": "git",
                "name": repo_name,
                "is_private": is_private,
                "description": description,
                "has_issues": arguments.get("has_issues", True)  # Added this line
            }

            # Only add project if specified (required for workspace repos, not for personal)
            if project_key:
                payload["project"] = {"key": project_key}

            url = f"https://api.bitbucket.org/2.0/repositories/{workspace}/{repo_name.lower()}"
            response = requests.post(url, json=payload, auth=auth, headers=headers, verify=VERIFY)

            if response.status_code in (200, 201):
                repo_url = response.json().get('links', {}).get('html', {}).get('href', '')
                return [types.TextContent(
                    type="text",
                    text=f"Repository created successfully in workspace '{workspace}'\nURL: {repo_url}"
                )]
            else:
                error_msg = format_permission_error(response.text)
                if workspace == "kallows" and "permission" in error_msg.lower():
                    error_msg += "\n\nTip: You can try creating the repository in your personal workspace by setting workspace='~'"
                
                return [types.TextContent(
                    type="text",
                    text=f"Failed to create repository: {response.status_code}\n{error_msg}",
                    isError=True
                )]

        elif name == "bb_search_repositories":
            workspace = arguments.get("workspace", "kallows")
            query = arguments.get("query")
            page = arguments.get("page", 1)
            pagelen = min(arguments.get("pagelen", 10), 100)  # Cap at 100

            if is_server_mode():
                # Bitbucket Server/DC: use /rest/api/1.0/repos with name filter
                if not BITBUCKET_BASE_URL:
                    return [types.TextContent(type="text", text="BITBUCKET_BASE_URL is required for server/DC mode", isError=True)]

                base = BITBUCKET_BASE_URL.rstrip('/')
                url = f"{base}/rest/api/1.0/repos"

                # Try to extract name filter from Bitbucket Cloud-style query: name ~ "pattern"
                name_filter = None
                if isinstance(query, str):
                    # Support cloud-like query: name ~ "pattern" or name ~ 'pattern'
                    m = re.search(r'name\s*~\s*"([^"]+)"', query) or re.search(r"name\s*~\s*'([^']+)'", query)
                    if m:
                        name_filter = m.group(1)
                    else:
                        # Fallback: use raw query as name substring
                        name_filter = query.strip()

                start = max(0, (page - 1) * pagelen)
                params = {
                    'start': start,
                    'limit': pagelen
                }
                if name_filter:
                    params['name'] = name_filter

                response = requests.get(url, params=params, auth=auth, headers=headers, verify=VERIFY)
                if response.status_code == 200:
                    data = response.json()
                    values = data.get('values', [])
                    results = []
                    for repo in values:
                        links = repo.get('links', {})
                        self_links = links.get('self', [])
                        html_url = self_links[0].get('href') if self_links else ""
                        project_key = (repo.get('project') or {}).get('key', '')
                        results.append({
                            'name': repo.get('name'),
                            'slug': repo.get('slug'),
                            'project_key': project_key,
                            'url': html_url or ""
                        })

                    is_last = data.get('isLastPage', True)
                    size = data.get('size', len(values))
                    return [types.TextContent(
                        type="text",
                        text=(
                            f"Found {len(results)} repositories:\n\n" +
                            '\n\n'.join([
                                f"• {r['name']} (project {r['project_key']})\n"
                                f"  URL: {r['url']}"
                                for r in results
                            ]) +
                            f"\n\nPage {page} | Total (page size): {size} | " +
                            ("More results available" if not is_last else "End of results")
                        )
                    )]
                else:
                    return [types.TextContent(
                        type="text",
                        text=f"Failed to search repositories: {response.status_code}\n{response.text}",
                        isError=True
                    )]
            else:
                # Bitbucket Cloud
                url = f"https://api.bitbucket.org/2.0/repositories/{workspace}"
                params = {
                    'q': query,
                    'page': page,
                    'pagelen': pagelen
                }
                response = requests.get(url, params=params, auth=auth, headers=headers, verify=VERIFY)

                if response.status_code == 200:
                    repos = response.json()

                    # Format the results nicely
                    results = []
                    for repo in repos.get('values', []):
                        repo_info = {
                            'name': repo.get('name'),
                            'full_name': repo.get('full_name'),
                            'description': repo.get('description', 'No description'),
                            'created_on': repo.get('created_on'),
                            'updated_on': repo.get('updated_on'),
                            'size': repo.get('size', 0),
                            'language': repo.get('language', 'Unknown'),
                            'has_wiki': repo.get('has_wiki', False),
                            'is_private': repo.get('is_private', True),
                            'url': repo.get('links', {}).get('html', {}).get('href', '')
                        }
                        results.append(repo_info)

                    # Add pagination info
                    pagination = {
                        'page': page,
                        'pagelen': pagelen,
                        'size': repos.get('size', 0),
                        'next': 'next' in repos.get('links', {}),
                        'previous': 'previous' in repos.get('links', {})
                    }

                    return [types.TextContent(
                        type="text",
                        text=f"Found {len(results)} repositories:\n\n" + 
                             '\n\n'.join([
                                f"• {r['name']}\n"
                                f"  Description: {r['description']}\n"
                                f"  Language: {r['language']}\n"
                                f"  URL: {r['url']}"
                                for r in results
                             ]) +
                             f"\n\nPage {pagination['page']} | "
                             f"Total results: {pagination['size']} | "
                             f"{'More results available' if pagination['next'] else 'End of results'}"
                    )]
                else:
                    return [types.TextContent(
                        type="text",
                        text=f"Failed to search repositories: {response.status_code}\n{format_permission_error(response.text)}",
                        isError=True
                    )]

        elif name == "bb_create_branch":
            repo_slug = arguments.get("repo_slug")
            branch_name = arguments.get("branch")
            start_point = arguments.get("start_point", "main")

            if is_server_mode():
                # Bitbucket Server/DC flow
                if not BITBUCKET_BASE_URL:
                    return [types.TextContent(type="text", text="BITBUCKET_BASE_URL is required for server/DC mode", isError=True)]
                project_key = arguments.get("project_key")
                if not project_key:
                    return [types.TextContent(type="text", text="project_key is required for Bitbucket Server/DC branch creation", isError=True)]

                base = BITBUCKET_BASE_URL.rstrip('/')

                # Resolve default branch if start_point not provided
                if not start_point:
                    repo_url = f"{base}/rest/api/1.0/projects/{project_key}/repos/{repo_slug}"
                    repo_resp = requests.get(repo_url, auth=auth, headers=headers, verify=VERIFY)
                    if repo_resp.status_code != 200:
                        return [types.TextContent(type="text", text=f"Failed to get repo details: {repo_resp.status_code}\n{repo_resp.text}", isError=True)]
                    start_point = (repo_resp.json().get('defaultBranch') or {}).get('displayId') or "main"

                create_url = f"{base}/rest/api/1.0/projects/{project_key}/repos/{repo_slug}/branches"
                payload = {
                    "name": branch_name,
                    "startPoint": f"refs/heads/{start_point}",
                    "message": f"Create branch {branch_name} via MCP"
                }
                response = requests.post(create_url, json=payload, auth=auth, headers=headers, verify=VERIFY)
                if response.status_code in (200, 201):
                    branch_url = f"{base}/projects/{project_key}/repos/{repo_slug}/browse?at=refs%2Fheads%2F{branch_name}"
                    return [types.TextContent(type="text", text=f"Branch '{branch_name}' created successfully\nURL: {branch_url}")]
                else:
                    return [types.TextContent(type="text", text=f"Failed to create branch: {response.status_code}\n{response.text}", isError=True)]
            else:
                # Bitbucket Cloud flow
                workspace = arguments.get("workspace", "kallows")
                # First get the hash of the start point
                ref_url = f"https://api.bitbucket.org/2.0/repositories/{workspace}/{repo_slug}/refs/branches/{start_point}"
                ref_response = requests.get(ref_url, auth=auth, headers=headers, verify=VERIFY)
                if ref_response.status_code != 200:
                    return [types.TextContent(
                        type="text",
                        text=f"Failed to get start point reference: {ref_response.status_code}\n{format_permission_error(ref_response.text)}",
                        isError=True
                    )]
                start_hash = ref_response.json()['target']['hash']
                # Create the new branch
                url = f"https://api.bitbucket.org/2.0/repositories/{workspace}/{repo_slug}/refs/branches"
                payload = {
                    "name": branch_name,
                    "target": {
                        "hash": start_hash
                    }
                }
                response = requests.post(url, json=payload, auth=auth, headers=headers, verify=VERIFY)
                if response.status_code in (200, 201):
                    branch_url = response.json().get('links', {}).get('html', {}).get('href', '')
                    return [types.TextContent(type="text", text=f"Branch '{branch_name}' created successfully\nURL: {branch_url}")]
                else:
                    return [types.TextContent(type="text", text=f"Failed to create branch: {response.status_code}\n{format_permission_error(response.text)}", isError=True)]

        elif name == "bb_delete_repository":
            workspace = arguments.get("workspace", "kallows")
            if workspace == "~":
                user_url = "https://api.bitbucket.org/2.0/user"
                user_response = requests.get(user_url, auth=auth, headers=headers, verify=VERIFY)
                if user_response.status_code != 200:
                    return [types.TextContent(
                        type="text",
                        text=f"Failed to get user info: {user_response.status_code} - {format_permission_error(user_response.text)}",
                        isError=True
                    )]
                workspace = user_response.json().get('username')

            repo_slug = arguments.get("repo_slug")
            url = f"https://api.bitbucket.org/2.0/repositories/{workspace}/{repo_slug}"
            response = requests.delete(url, auth=auth, headers=headers, verify=VERIFY)

            if response.status_code == 204:
                return [types.TextContent(
                    type="text",
                    text=f"Repository {repo_slug} deleted successfully from workspace '{workspace}'"
                )]
            else:
                error_msg = format_permission_error(response.text)
                if workspace == "kallows" and "permission" in error_msg.lower():
                    error_msg += "\n\nTip: You can try deleting the repository from your personal workspace by setting workspace='~'"
                
                return [types.TextContent(
                    type="text",
                    text=f"Failed to delete repository: {response.status_code}\n{error_msg}",
                    isError=True
                )]

        elif name == "bb_read_file":
            workspace = arguments.get("workspace", "kallows")
            repo_slug = arguments.get("repo_slug")
            file_path = arguments.get("path")
            branch = arguments.get("branch", "main")

            if is_server_mode():
                # Bitbucket Server/DC flow
                if not BITBUCKET_BASE_URL:
                    return [types.TextContent(type="text", text="BITBUCKET_BASE_URL is required for server/DC mode", isError=True)]
                
                base = BITBUCKET_BASE_URL.rstrip('/')
                
                # Get project_key - either from argument or by fetching repo info
                project_key = arguments.get("project_key")
                if not project_key:
                    # Try to find repo by searching or use a common pattern
                    # First, try to search for the repo to get its project_key
                    search_url = f"{base}/rest/api/1.0/repos"
                    search_params = {"name": repo_slug, "limit": 100}
                    search_resp = requests.get(search_url, params=search_params, auth=auth, headers=headers, verify=VERIFY)
                    if search_resp.status_code == 200:
                        repos = search_resp.json().get('values', [])
                        for repo in repos:
                            if repo.get('slug') == repo_slug or repo.get('name') == repo_slug:
                                project_key = (repo.get('project') or {}).get('key')
                                break
                    
                    # If still not found, try fetching repo info directly (may need project_key)
                    # As fallback, try common project keys or workspace
                    if not project_key:
                        # Try fetching from repo search with slug
                        repo_info_url = f"{base}/rest/api/1.0/repos"
                        repo_info_params = {"name": repo_slug}
                        repo_info_resp = requests.get(repo_info_url, params=repo_info_params, auth=auth, headers=headers, verify=VERIFY)
                        if repo_info_resp.status_code == 200:
                            repos = repo_info_resp.json().get('values', [])
                            for repo in repos:
                                if repo.get('slug') == repo_slug:
                                    project_key = (repo.get('project') or {}).get('key')
                                    break
                
                if not project_key:
                    return [types.TextContent(
                        type="text",
                        text="Could not determine project_key for repository. Please provide project_key parameter for Server/DC mode.",
                        isError=True
                    )]
                
                # Use the raw endpoint for Server/DC to get file content
                url = f"{base}/rest/api/1.0/projects/{project_key}/repos/{repo_slug}/raw/{file_path}"
                params = {"at": f"refs/heads/{branch}"}
                response = requests.get(url, params=params, auth=auth, headers=headers, verify=VERIFY)
                
                if response.status_code == 200:
                    return [types.TextContent(
                        type="text",
                        text=response.text
                    )]
                else:
                    return [types.TextContent(
                        type="text",
                        text=f"Failed to read file: {response.status_code}\n{format_permission_error(response.text)}",
                        isError=True
                    )]
            else:
                # Bitbucket Cloud flow
                url = f"https://api.bitbucket.org/2.0/repositories/{workspace}/{repo_slug}/src/{branch}/{file_path}"
                response = requests.get(url, auth=auth, verify=VERIFY)

                if response.status_code == 200:
                    return [types.TextContent(
                        type="text",
                        text=response.text
                    )]
                else:
                    return [types.TextContent(
                        type="text",
                        text=f"Failed to read file: {response.status_code}\n{format_permission_error(response.text)}",
                        isError=True
                    )]

        elif name == "bb_write_file":
            workspace = arguments.get("workspace", "kallows")
            repo_slug = arguments.get("repo_slug")
            file_path = arguments.get("path")
            content = arguments.get("content")
            message = arguments.get("message", "Update file via MCP")
            branch = arguments.get("branch", "main")

            url = f"https://api.bitbucket.org/2.0/repositories/{workspace}/{repo_slug}/src"
            
            # Prepare form data for file upload
            files = {
                file_path: (None, content)
            }
            data = {
                'message': message,
                'branch': branch
            }

            response = requests.post(url, auth=auth, files=files, data=data, verify=VERIFY)

            if response.status_code in (200, 201):
                return [types.TextContent(
                    type="text",
                    text=f"File {file_path} updated successfully"
                )]
            else:
                return [types.TextContent(
                    type="text",
                    text=f"Failed to write file: {response.status_code}\n{format_permission_error(response.text)}",
                    isError=True
                )]

        elif name == "bb_create_issue":
            workspace = arguments.get("workspace", "kallows")
            repo_slug = arguments.get("repo_slug")
            title = arguments.get("title")
            content = arguments.get("content")
            kind = arguments.get("kind", "task")
            priority = arguments.get("priority", "minor")

            url = f"https://api.bitbucket.org/2.0/repositories/{workspace}/{repo_slug}/issues"
            
            payload = {
                "title": title,
                "content": {"raw": content},
                "kind": kind,
                "priority": priority
            }

            response = requests.post(url, json=payload, auth=auth, headers=headers, verify=VERIFY)

            if response.status_code in (200, 201):
                issue_id = response.json().get('id')
                issue_url = response.json().get('links', {}).get('html', {}).get('href', '')
                return [types.TextContent(
                    type="text",
                    text=f"Issue created successfully\nID: {issue_id}\nURL: {issue_url}"
                )]
            else:
                return [types.TextContent(
                    type="text",
                    text=f"Failed to create issue: {response.status_code}\n{format_permission_error(response.text)}",
                    isError=True
                )]

        elif name == "bb_delete_issue":
            workspace = arguments.get("workspace", "kallows")
            repo_slug = arguments.get("repo_slug")
            issue_id = arguments.get("issue_id")

            url = f"https://api.bitbucket.org/2.0/repositories/{workspace}/{repo_slug}/issues/{issue_id}"
            response = requests.delete(url, auth=auth, headers=headers, verify=VERIFY)

            if response.status_code == 204:
                return [types.TextContent(
                    type="text",
                    text=f"Issue {issue_id} deleted successfully"
                )]
            else:
                return [types.TextContent(
                    type="text",
                    text=f"Failed to delete issue: {response.status_code}\n{format_permission_error(response.text)}",
                    isError=True
                )]

        elif name == "bb_delete_file":
            workspace = arguments.get("workspace", "kallows")
            repo_slug = arguments.get("repo_slug")
            file_path = arguments.get("path")
            message = arguments.get("message", "Delete file via MCP")
            branch = arguments.get("branch", "main")

            url = f"https://api.bitbucket.org/2.0/repositories/{workspace}/{repo_slug}/src"
            
            # In Bitbucket, file deletion is done by posting an empty file
            files = {
                file_path: (None, "")
            }
            data = {
                'message': message,
                'branch': branch
            }

            response = requests.post(url, auth=auth, files=files, data=data, verify=VERIFY)

            if response.status_code in (200, 201):
                return [types.TextContent(
                    type="text",
                    text=f"File {file_path} deleted successfully"
                )]
            else:
                return [types.TextContent(
                    type="text",
                    text=f"Failed to delete file: {response.status_code}\n{format_permission_error(response.text)}",
                    isError=True
                )]

        elif name == "bb_create_pull_request":
            workspace = arguments.get("workspace", "kallows")
            repo_slug = arguments.get("repo_slug")
            title = arguments.get("title")
            description = arguments.get("description", "")
            source_branch = arguments.get("source_branch")
            destination_branch = arguments.get("destination_branch", "main")
            close_source_branch = arguments.get("close_source_branch", True)

            url = f"https://api.bitbucket.org/2.0/repositories/{workspace}/{repo_slug}/pullrequests"
            
            payload = {
                "title": title,
                "description": description,
                "source": {
                    "branch": {
                        "name": source_branch
                    }
                },
                "destination": {
                    "branch": {
                        "name": destination_branch
                    }
                },
                "close_source_branch": close_source_branch
            }

            response = requests.post(url, json=payload, auth=auth, headers=headers, verify=VERIFY)

            if response.status_code in (200, 201):
                pr_id = response.json().get('id')
                pr_url = response.json().get('links', {}).get('html', {}).get('href', '')
                return [types.TextContent(
                    type="text",
                    text=f"Pull request created successfully\nID: {pr_id}\nURL: {pr_url}"
                )]

        elif name == "bb_list_branches_created_by_user":
            if not is_server_mode() or not BITBUCKET_BASE_URL:
                return [types.TextContent(type="text", text="This tool requires Bitbucket Server/DC. Set BITBUCKET_BASE_URL and BITBUCKET_MODE=server.", isError=True)]

            base = BITBUCKET_BASE_URL.rstrip('/')
            project_key = arguments.get("project_key")
            repo_slug = arguments.get("repo_slug")
            author = (arguments.get("author") or BITBUCKET_USERNAME or "").lower()
            months = max(1, arguments.get("months", 3))

            # Fetch repository to get default branch
            repo_url = f"{base}/rest/api/1.0/projects/{project_key}/repos/{repo_slug}"
            repo_resp = requests.get(repo_url, auth=auth, headers=headers, verify=VERIFY)
            if repo_resp.status_code != 200:
                return [types.TextContent(type="text", text=f"Failed to get repo details: {repo_resp.status_code}\n{repo_resp.text}", isError=True)]
            repo_info = repo_resp.json()
            default_branch = ((repo_info.get('defaultBranch') or {}).get('displayId')) or "main"
            default_ref = f"refs/heads/{default_branch}"

            # List branches
            list_url = f"{base}/rest/api/1.0/projects/{project_key}/repos/{repo_slug}/branches"
            start = 0
            limit = 100
            branches = []
            while True:
                params = {"start": start, "limit": limit}
                list_resp = requests.get(list_url, params=params, auth=auth, headers=headers, verify=VERIFY)
                if list_resp.status_code != 200:
                    return [types.TextContent(type="text", text=f"Failed to list branches: {list_resp.status_code}\n{list_resp.text}", isError=True)]
                data = list_resp.json()
                branches.extend(data.get("values", []))
                if data.get("isLastPage", True):
                    break
                start = data.get("nextPageStart", 0)

            cutoff = datetime.now(timezone.utc) - timedelta(days=30*months)
            results = []

            # For each branch, find earliest unique commit vs default branch
            for br in branches:
                display_id = br.get("displayId") or ""
                if not display_id or display_id == default_branch:
                    continue
                to_ref = f"refs/heads/{display_id}"

                compare_url = f"{base}/rest/api/1.0/projects/{project_key}/repos/{repo_slug}/compare/commits"
                # Page through to get the oldest commit in the compare
                c_start = 0
                c_limit = 100
                last_values = None
                while True:
                    c_params = {
                        "from": default_ref,
                        "to": to_ref,
                        "start": c_start,
                        "limit": c_limit
                    }
                    comp_resp = requests.get(compare_url, params=c_params, auth=auth, headers=headers, verify=VERIFY)
                    if comp_resp.status_code != 200:
                        # If compare fails (e.g., branch equals default), skip
                        last_values = None
                        break
                    comp_data = comp_resp.json()
                    values = comp_data.get("values", [])
                    if values:
                        last_values = values
                    if comp_data.get("isLastPage", True):
                        break
                    c_start = comp_data.get("nextPageStart", 0)

                if not last_values:
                    continue

                # Oldest is the last item of last page we fetched
                earliest = last_values[-1]
                auth_obj = earliest.get("author", {}) or {}
                author_name = (auth_obj.get("name") or "").lower()
                author_email = (auth_obj.get("emailAddress") or "").lower()
                ts_ms = earliest.get("authorTimestamp") or 0
                created_at = datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc)

                # Match by username or email substring
                if author and (author in author_name or author in author_email):
                    if created_at >= cutoff:
                        results.append({
                            "branch": display_id,
                            "created_at": created_at.isoformat(),
                            "author": author_name or author_email
                        })

            if not results:
                return [types.TextContent(type="text", text="No branches found for the specified user in the requested time window.")]

            results.sort(key=lambda r: r["created_at"], reverse=True)
            lines = [
                f"• {r['branch']}  (created {r['created_at']}, author: {r['author']})"
                for r in results
            ]
            return [types.TextContent(type="text", text="Branches created by user in the last period:\n\n" + "\n".join(lines))]

        elif name == "bb_list_repositories_created_by_user":
            if not is_server_mode() or not BITBUCKET_BASE_URL:
                return [types.TextContent(type="text", text="This tool requires Bitbucket Server/DC. Set BITBUCKET_BASE_URL and BITBUCKET_MODE=server.", isError=True)]

            base = BITBUCKET_BASE_URL.rstrip('/')
            project_key = arguments.get("project_key")
            author = (arguments.get("author") or BITBUCKET_USERNAME or "").lower()
            months = max(1, int(arguments.get("months", 3)))
            repo_page_limit = min(int(arguments.get("pagelen", 50)), 100)

            # Page through repos in the project
            list_url = f"{base}/rest/api/1.0/projects/{project_key}/repos"
            start = 0
            repos = []
            while True:
                params = {"start": start, "limit": repo_page_limit}
                resp = requests.get(list_url, params=params, auth=auth, headers=headers, verify=VERIFY)
                if resp.status_code != 200:
                    return [types.TextContent(type="text", text=f"Failed to list repositories: {resp.status_code}\n{resp.text}", isError=True)]
                data = resp.json()
                repos.extend(data.get("values", []))
                if data.get("isLastPage", True):
                    break
                start = data.get("nextPageStart", 0)

            cutoff = datetime.now(timezone.utc) - timedelta(days=30*months)
            created_by_user = []

            for r in repos:
                repo_slug = r.get("slug")
                repo_name = r.get("name") or repo_slug or ""
                if not repo_slug:
                    continue

                # Get default branch
                repo_url = f"{base}/rest/api/1.0/projects/{project_key}/repos/{repo_slug}"
                repo_resp = requests.get(repo_url, auth=auth, headers=headers, verify=VERIFY)
                if repo_resp.status_code != 200:
                    continue
                repo_info = repo_resp.json()
                default_branch = ((repo_info.get('defaultBranch') or {}).get('displayId')) or "main"
                default_ref = f"refs/heads/{default_branch}"

                # Get earliest commit on default branch by paging to last page
                commits_url = f"{base}/rest/api/1.0/projects/{project_key}/repos/{repo_slug}/commits"
                c_start = 0
                c_limit = 100
                last_values = None
                while True:
                    c_params = {"until": default_ref, "start": c_start, "limit": c_limit}
                    c_resp = requests.get(commits_url, params=c_params, auth=auth, headers=headers, verify=VERIFY)
                    if c_resp.status_code != 200:
                        last_values = None
                        break
                    c_data = c_resp.json()
                    values = c_data.get("values", [])
                    if values:
                        last_values = values
                    if c_data.get("isLastPage", True):
                        break
                    c_start = c_data.get("nextPageStart", 0)

                if not last_values:
                    continue

                earliest = last_values[-1]
                auth_obj = earliest.get("author", {}) or {}
                author_name = (auth_obj.get("name") or "").lower()
                author_email = (auth_obj.get("emailAddress") or "").lower()
                ts_ms = earliest.get("authorTimestamp") or 0
                created_at = datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc)

                if author and (author in author_name or author in author_email) and created_at >= cutoff:
                    links = (r.get("links") or {})
                    self_links = links.get("self", [])
                    repo_html = self_links[0].get("href") if self_links else f"{base}/projects/{project_key}/repos/{repo_slug}/browse"
                    created_by_user.append({
                        "name": repo_name,
                        "slug": repo_slug,
                        "created_at": created_at.isoformat(),
                        "url": repo_html
                    })

            if not created_by_user:
                return [types.TextContent(type="text", text="No repositories found created by the specified user in the requested time window.")]

            created_by_user.sort(key=lambda r: r["created_at"], reverse=True)
            text = "Repositories likely created by user in the last period:\n\n" + "\n\n".join(
                [f"• {r['name']} ({r['slug']})\n  Created: {r['created_at']}\n  URL: {r['url']}" for r in created_by_user]
            )
            return [types.TextContent(type="text", text=text)]

        raise ValueError(f"Unknown tool: {name}")
        
    except Exception as e:
        return [types.TextContent(
            type="text",
            text=f"Operation failed: {str(e)}",
            isError=True
        )]

async def main():
    """Run the Bitbucket MCP server using stdin/stdout streams."""
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="bitbucket-api",
                server_version="0.1.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )

if __name__ == "__main__":
    asyncio.run(main())