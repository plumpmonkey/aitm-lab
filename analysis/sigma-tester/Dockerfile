# Sigma rule tester for Task 6. Run it from the aitm-lab directory with:
#     docker compose run --rm sigma
# It is built the first time you run it, which needs internet access.
FROM python:3.12-slim

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tshark \
 && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir pysigma==2.0.1 pysigma-backend-sqlite==2.1.1

# The rule checks look up MITRE ATT&CK and D3FEND names. Fetch that data now,
# while the build has internet access; pySigma keeps it in ~/.cache/pysigma.
RUN python3 -c "from sigma.data import mitre_attack, mitre_d3fend; mitre_attack.mitre_attack_tactics; mitre_d3fend.mitre_d3fend_tactics"

# Rules, sample data and this script are mounted from ./analysis at run time,
# so edits to a rule take effect without rebuilding.
WORKDIR /lab
CMD ["python3", "/lab/analysis/sigma-tester/test_rules.py"]
