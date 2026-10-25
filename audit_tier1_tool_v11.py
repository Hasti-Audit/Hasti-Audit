import urllib.request
import json

# 1. Download v11 directly from your GitHub
url = "https://raw.githubusercontent.com/Hasti-Audit/Hasti-Audit/main/audit_tier1_tool_v11.py"
v11_path = "/content/audit_tier1_tool_v11.py"

print("Downloading v11 from GitHub...")
urllib.request.urlretrieve(url, v11_path)
print("✅ Downloaded v11.\n")

# 2. Import and run
import sys
import importlib.util

# Load the module dynamically
spec = importlib.util.spec_from_file_location("audit_tier1_tool_v11", v11_path)
v11_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v11_module)

# 3. Test on our real-world file
test_file = "/content/patient_data.py"
print("--- STARTING v11 REAL-WORLD AUDIT ---")
result = v11_module.run_audit_v11(test_file)

# Print results
print(json.dumps(result, indent=4))
