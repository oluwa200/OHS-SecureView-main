import json, os, asyncio, base64, httpx
from dotenv import load_dotenv
load_dotenv()

async def main():
    client_id = os.getenv("AIKIDO_CLIENT_ID", "")
    client_secret = os.getenv("AIKIDO_CLIENT_SECRET", "")
    credentials = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
    
    async with httpx.AsyncClient(verify=False, timeout=30) as client:
        r = await client.post("https://app.aikido.dev/api/oauth/token",
            headers={"Authorization": f"Basic {credentials}"},
            data={"grant_type": "client_credentials"})
        token = r.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        
        # Get first few issues to see the structure
        r = await client.get("https://app.aikido.dev/api/public/v1/issues/export?format=json&status=open",
            headers=headers, timeout=60)
        issues = r.json()
        if isinstance(issues, dict):
            print(f"Response keys: {list(issues.keys())}")
            issues = issues.get("issues", issues.get("value", issues.get("data", [])))
        
        print(f"Total issues: {len(issues)}")
        if issues:
            print(f"\nFirst issue keys: {list(issues[0].keys())}")
            print(f"\nFirst 3 issues (truncated):")
            for i in issues[:3]:
                print(json.dumps(i, indent=2, default=str)[:400])
                print("---")

asyncio.run(main())
