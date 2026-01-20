
[![Live Resume](https://img.shields.io/badge/Live%20Resume-grey?style=flat&labelColor=red&logo=readthedocs)](https://dafantestapletonresume.link)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-grey?style=flat&labelColor=0A66C2&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/dafante-stapleton/)
[![GitHub](https://img.shields.io/badge/Profile-grey?style=flat&labelColor=181717&logo=github&logoColor=white)](https://github.com/D-Stap)
[![Credly](https://img.shields.io/badge/Credly-grey?style=flat&labelColor=FF6B00&logo=credly&logoColor=white)](https://www.credly.com/users/dafante-stapleton)
[![Email](https://img.shields.io/badge/Email-grey?style=flat&labelColor=EA4335&logo=gmail&logoColor=white)](mailto:dafante.e.stapleton.com)


# iam-privilege-checker

A small, focused command-line tool for statically analyzing AWS IAM policy JSON.
It helps detect wildcard permissions and other high-risk patterns so you can
catch and remediate dangerous policies before they reach production

Why this matters
Overly permissive IAM policies are a leading cause of cloud security incidents.
This tool gives fast, actionable feedback so reviewers and CI pipelines can
reduce privilege blast radius early in the delivery process.

Quick usage
Run the checker against a policy file:

```
python iam-checker.py examples/example_policy.json
```

Output
The script prints concise findings and recommendations to help you scope down
permissions and remove wildcard access.

Example output
Below are two example runs. The first shows a policy that exposes all resources
via a wildcard resource. The second shows a policy that contains a high-risk
action pattern.

```
$ python iam-checker.py examples/bad_policy.json
Analyzing IAM policy: examples/bad_policy.json

FINDING: Resource '*' found — full access to all resources

Scan complete.
```

```
$ python iam-checker.py examples/iam_admin.json
Analyzing IAM policy: examples/iam_admin.json

FINDING: High Risk: action 'iam:*' matches risky pattern

Scan complete.
```
<img width="664" height="392" alt="Screenshot 2025-11-19 at 21 57 20" src="https://github.com/user-attachments/assets/9726ca04-6487-4458-af19-73d230ac54d5" />
