package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
)

func main() {

	// Check if there are at least two arguments 
	if len(os.Args) < 3 {
		log.Fatal("Usage: go run main.go <baseline_file.json> <pr_file.json>")
	}

	// Read the baseline JSON file
	baselineFile := filepath.Clean(os.Args[1])
	baselineJSON, err := ioutil.ReadFile(baselineFile)
	if err != nil {
		log.Fatalf("Failed to read the baseline JSON file: %v", err)
	}

	// Read the PR JSON file
	prFile := filepath.Clean(os.Args[2])
	prJSON, err := ioutil.ReadFile(prFile)
	if err != nil {
		log.Fatalf("Failed to read the PR JSON file: %v", err)
	}

	// Parse the Baseline JSON scan
	var baselineData map[string]interface{}
	err = json.Unmarshal(baselineJSON, &baselineData)
	if err != nil {
		log.Fatalf("Failed to parse the Baseline JSON scan: %v", err)
	}

	// Parse the PR JSON scan
	var prData map[string]interface{}
	err = json.Unmarshal(prJSON, &prData)
	if err != nil {
		log.Fatalf("Failed to parse the PR JSON scan: %v", err)
	}

	fmt.Printf("\n")
	fmt.Printf("Running Snyk Code PR Diff")
	fmt.Printf("\n")

	// Extract the "results" array from the Baseline scan
	baselineResults, ok := extractResults(baselineData)
	if !ok {
		log.Fatal("Failed to extract 'results' from the Baseline scan")
	}

	// Extract the "results" array from the PR scan
	prResults, ok := extractResults(prData)
	if !ok {
		log.Fatal("Failed to extract 'results' from PR scan")
	}

	// Find the indices of new fingerprints from the PR results
	newIndices := findNewFingerprintIndices(baselineResults, prResults)

	// Extract the new issues objects from the PR results
	newIssues := extractNewIssues(prResults, newIndices)

	// Count the number of new issues found from the PR results
	issueCount := len(newIssues)

	// Output the new issues from the PR results
	for _, result := range newIssues {
		level, message, uri, startLine := extractIssueData(result)
		level = strings.Replace(level, "note", "Low", 1)
		level = strings.Replace(level, "warning", "Medium", 1)
		level = strings.Replace(level, "error", "High", 1)
		fmt.Printf("✗ Severity: [%s]\n", level)
		fmt.Printf("Path: %s\n", uri)
		fmt.Printf("Start Line: %d\n", startLine)
		fmt.Printf("Message: %s\n", message)
		fmt.Printf("\n")
	}

	// Output the count new issues found from the PR results
	if issueCount > 0 {
		fmt.Printf("\n")
		fmt.Printf("Total issues found: %d\n", issueCount)

		// Replace the "results" array in the PR scan with only the new issues found
		prData["runs"].([]interface{})[0].(map[string]interface{})["results"] = newIssues

		// Convert the new PR data to JSON
		updatedPRScan, err := json.Marshal(prData)
		if err != nil {
			log.Fatalf("Failed to convert updated data to JSON: %v", err)
		}

		// Write the updated PR diff scan to a file
		err = ioutil.WriteFile("snyk_code_pr_diff_scan.json", updatedPRScan, 0644)
		if err != nil {
			log.Fatalf("Failed to write updated data to file: %v", err)
		}
    fmt.Printf("\n")
		fmt.Println("Results saved in usnyk_code_pr_diff_scan.json")    
		os.Exit(1)
	}
  
  fmt.Printf("\n")
	fmt.Println("No issues found!")

}

// Extract the "results" array from the JSON data
func extractResults(data map[string]interface{}) ([]interface{}, bool) {
	runs, ok := data["runs"].([]interface{})
	if !ok {
		return nil, false
	}

	if len(runs) > 0 {
		results, ok := runs[0].(map[string]interface{})["results"].([]interface{})
		if !ok {
			return nil, false
		}
		return results, true
	}

	return nil, false
}

// Find the indices of the new fingerprints in the PR results array
func findNewFingerprintIndices(baselineResults, prResults []interface{}) []int {
	var newIndices []int

	for i, prResult := range prResults {
		prObject := prResult.(map[string]interface{})
		if prFingerprints, ok := prObject["fingerprints"].(map[string]interface{}); ok {
			matchFound := false
			for _, baselineResult := range baselineResults {
				baselineObject := baselineResult.(map[string]interface{})
				if baselineFingerprints, ok := baselineObject["fingerprints"].(map[string]interface{}); ok {
					// Ignore the "identity" key
					delete(baselineFingerprints, "identity")
					delete(prFingerprints, "identity")

					match := fmt.Sprint(prFingerprints) == fmt.Sprint(baselineFingerprints)
					if match {
						matchFound = true
						break
					}
				}
			}
			if !matchFound {
				newIndices = append(newIndices, i)
			}
		}
	}

	return newIndices
}

// Extract new issues objects from the PR "results" array
func extractNewIssues(results []interface{}, indices []int) []interface{} {
	var newIssues []interface{}

	for _, idx := range indices {
		newIssues = append(newIssues, results[idx])
	}

	return newIssues
}

// Extract new issue data from the results to output to the console
func extractIssueData(result interface{}) (string, string, string, int) {
	resultObj := result.(map[string]interface{})
	level := resultObj["level"].(string)
	message := resultObj["message"].(map[string]interface{})["text"].(string)
	locations := resultObj["locations"].([]interface{})
	uri := locations[0].(map[string]interface{})["physicalLocation"].(map[string]interface{})["artifactLocation"].(map[string]interface{})["uri"].(string)
	startLine := locations[0].(map[string]interface{})["physicalLocation"].(map[string]interface{})["region"].(map[string]interface{})["startLine"].(float64)
	return level, message, uri, int(startLine)
}
