import json
data = json.load(open("data-dev/aikido_report.json"))
apps = data.get("applications", [])
print(f"Total apps: {len(apps)}")
for app in apps[:5]:
    name = app.get("name", "?")
    issues_count = len(app.get("issues", []))
    summary = app.get("summary", {})
    print(f"\n  App: {name} | Issues: {issues_count}")
    print(f"    Critical: {summary.get('critical',0)} | High: {summary.get('high',0)} | Breached: {summary.get('breached',0)}")
    if app.get("issues"):
        sample = app["issues"][0]
        print(f"    Sample keys: {list(sample.keys())}")
        print(f"    Title: {sample.get('title','')[:80]}")
        print(f"    Severity: {sample.get('severity')} | Type: {sample.get('type')} | Package: {sample.get('package')}")
