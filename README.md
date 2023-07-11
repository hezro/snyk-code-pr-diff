# Snyk Code PR Diff

Fail Snyk Code CLI scans only if there are new issues introduced (similar to Snyk Code PR checks).
Gets the delta between two Snyk Code JSON files before failing the scan. Particularly useful when running [Snyk CLI](https://github.com/snyk/cli) scans in your local environment, git hooks, CI/CD etc.


Compares two Snyk Code JSON files to provide details on:
- New vulnerabilities not found in the baseline scan

## Prerequisites
- Must provide two Snyk Code JSON files: one baseline scan and one scan where code changes have occurred


## Supported Snyk products

| Product | Supported |
| ---- | --------- |
| Code   | ✅     |
| Open Source    | ❌        |
| Container   | ❌        |
| IaC   | ❌         |

## Usage
- Run a Snyk Code scan and output a JSON file as the baseline.
- Run another Snyk Code scan that has code changes and output a JSON file.
- Usage: `snyk-code-pr-diff` `<baseline_scan.json>` `<pr_scan.json>`
- Example: ```snyk-code-pr-diff-amd64-linux /home/runner/work/goof/goof/snyk_code_baseline.json /home/runner/work/goof/goof/snyk_code_pr.json ```
  

## Examples
- GitHub Action example: https://github.com/hezro/snyk-code-pr-diff/blob/main/examples/github-action-baseline-scan-and-pr-scan.yml

## GitHub Action Screenshot
![image](https://github.com/hezro/snyk-code-pr-diff/assets/17459977/6934c42d-5f67-470b-b6aa-ec2b57cf2692)

