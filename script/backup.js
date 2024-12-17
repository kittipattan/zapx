// Configuration
var zapUrl = 'http://localhost:8080'; // Adjust if your ZAP is running elsewhere
var zapApiKey = ''; // Replace with your actual ZAP API key
var cweApiUrl = 'https://cwe-api.mitre.org/api/v1/cwe/weakness/'; // Placeholder for CWE API URL
var perplexityApiUrl = 'https://api.perplexity.ai/chat/completions';
var perplexityApiKey = ''; // Replace with your actual Perplexity API key

// Function to fetch alerts from ZAP
function getZAPAlerts() {
    var HttpClient = Java.type("org.apache.commons.httpclient.HttpClient");
    var GetMethod = Java.type("org.apache.commons.httpclient.methods.GetMethod");
    var URI = Java.type("java.net.URI");

    var client = new HttpClient();
    var uri = new URI(zapUrl + "/JSON/alert/view/alerts/?apikey=" + zapApiKey);
    var request = new GetMethod(uri.toString());

    try {
        client.executeMethod(request);
        var response = request.getResponseBodyAsString();
        var jsonResponse = JSON.parse(response);
        return jsonResponse.alerts || [];
    } catch (e) {
        print("Error fetching alerts: " + e);
        return [];
    }
}

// Function to get CWE details for an alert
function getCWEDetails(cweId) {
    var HttpClient = Java.type("org.apache.commons.httpclient.HttpClient");
    var GetMethod = Java.type("org.apache.commons.httpclient.methods.GetMethod");
    var URI = Java.type("java.net.URI");

    var client = new HttpClient();
    var uri = new URI(cweApiUrl + cweId);
    var request = new GetMethod(uri.toString());

    try {
        client.executeMethod(request);
        var response = request.getResponseBodyAsString();
        var jsonResponse = JSON.parse(response);

        // Extract relevant details if Weaknesses exist
        if (jsonResponse.Weaknesses && jsonResponse.Weaknesses.length > 0) {
            var weakness = jsonResponse.Weaknesses[0];

            return {
                id: weakness.ID,
                name: weakness.Name,
                description: weakness.Description,

                potentialMitigations: weakness.PotentialMitigations
            };
        } else {
            print("No weaknesses found for CWE-" + cweId);
            return null;
        }
        
    } catch (e) {
        print("Error fetching CWE details: " + e);
        return null;
    }
}

// Function to get mitigation plan from Perplexity API
function getMitigationPlan(alert, cweDetails) {
    var HttpClient = Java.type("org.apache.commons.httpclient.HttpClient");
    var PostMethod = Java.type("org.apache.commons.httpclient.methods.PostMethod");
    var URI = Java.type("java.net.URI");
    var StringRequestEntity = Java.type("org.apache.commons.httpclient.methods.StringRequestEntity");
    
    var client = new HttpClient();
    var requestData = {
        model: "llama-3.1-sonar-small-128k-online",
        messages: [
            { role: "system", content: "You are a security expert." },
            { role: "user", content: "What is the mitigation plan for: " 
                + JSON.stringify(alert) 
                + " with CWE Detail: " 
                + JSON.stringify(cweDetails) 
                + " Fill in replace all content in every blanket {...} from provided template, every {...} has content like Task: ... which is the task you have to replace that blanket: " 
                + "<h2>{Task: Input vulnerability name}</h2><br/>"
                + "<p>{Task: Provide vulnerability explanation}</p><br/>"
                + "<h3><strong>How It Works:</strong></h3><br/>"
                + "<p>{Task: Explain how it works}</p><br/>"
                + "<h4><strong>Example:</strong></h4>"
                + "<p>{Task: Give some examples of common situation when this vulnerability occur"
                + "(If there is vulnerability in code, please add it too in this format <code>{Vulnerable code}</code>)}</p>"
                + "<br/>"
                + "<h4><strong>Consequences:</strong></h4>"
                + "{Task: Give some example of the consequences from this vulnerability in list format}"
                + "<h3><strong>Detected Vulnerability:</strong></h3>"
                + "<code>{Task: Evidence from the alert (You may add more context for the evidence if needed)}</code>"
                + "<br/>"
                + "<h4><strong>Mitigation Strategies:</strong></h4>"
                + "{Task: Provide practical and context-specific mitigation strategies that can mitigate the vulnerability of the detected evidence. You might have many strategies, if so please write it in list format. You must provide practical code example based on the context of evidence and tech stack. Also, if there is a code, you must write in this format <code>{Your code}</code>}" 
                + " Remember, you must fill in with html tags if needed. You might need to see where to insert html tags."
                + " Please provide response to me only in HTML code. No markdown."
            }
        ]
    };
    
    var requestBody = JSON.stringify(requestData); // This is correct; no issue here
    
    try {
        var uri = new URI(perplexityApiUrl);
        var request = new PostMethod(uri.toString());
        request.setRequestEntity(new StringRequestEntity(requestBody, "application/json", "UTF-8"));
        request.addRequestHeader("Authorization", "Bearer " + perplexityApiKey);
    
        client.executeMethod(request);
        var response = request.getResponseBodyAsString();
        var responseContent = JSON.parse(response).choices[0].message.content.replace(/\n/g, '<br/>');
        
        return responseContent;  // Return parsed JSON response
    } catch (e) {
        print("Error fetching mitigation plan: " + e);  // Print error message
        return null;  // Return null in case of an error
    }

}

function recheck(response, cweDetails) {
    const cwe = JSON.stringify(cweDetails);
    var HttpClient = Java.type("org.apache.commons.httpclient.HttpClient");
    var PostMethod = Java.type(
    "org.apache.commons.httpclient.methods.PostMethod"
    );
    var URI = Java.type("java.net.URI");
    var StringRequestEntity = Java.type(
    "org.apache.commons.httpclient.methods.StringRequestEntity"
    );
    
    var client = new HttpClient();
    var requestData = {
    model: "llama-3.1-sonar-small-128k-online",
    messages: [
      { role: "system", content: "You are a security expert." },
      {
        role: "user",
        content:
          "Please recheck this mitigation plan: " +
          JSON.stringify(response) +
          " with the provided CWE information: " +
          cwe +
          " If the provided plan is valid, send back the same plan content (html), else revise it to correspond to the provided CWE and sent it back in html format same as the provided plan",
      },
    ],
    };
    
    var requestBody = JSON.stringify(requestData);
    
    try {
        var uri = new URI(perplexityApiUrl);
        var request = new PostMethod(uri.toString());
        request.setRequestEntity(new StringRequestEntity(requestBody, "application/json", "UTF-8"));
        request.addRequestHeader("Authorization", "Bearer " + perplexityApiKey);
        
        client.executeMethod(request);
        var response = request.getResponseBodyAsString();
        var responseContent = JSON.parse(response).choices[0].message.content.replace(/\n/g, '<br/>');
        
        return responseContent;  // Return parsed JSON response
    } catch (e) {
        print("Error fetching mitigation plan: " + e);
        return null;
    }
}

// Function to encode HTML special characters
function htmlEncode(str) {
    if (str === null) return "";
    
    return str.replace(/&/g, "&amp;")
              .replace(/</g, "&lt;")
              .replace(/>/g, "&gt;")
              .replace(/"/g, "&quot;")
              .replace(/'/g, "&#39;");
}

function saveReport(reportContent) {
    // Import Java file handling classes
    var FileWriter = Java.type("java.io.FileWriter");
    var BufferedWriter = Java.type("java.io.BufferedWriter");

    // Specify the file path (absolute or relative)
    var outputPath = "C:\\path\\to\\your\\file.html";

    try {
        // Create a writer to save the content
        var writer = new BufferedWriter(new FileWriter(outputPath));
        
        // Write the content to the file
        writer.write(reportContent);
        
        // Close the writer
        writer.close();
        print("HTML report successfully saved to: " + outputPath);
    } catch (e) {
        print("Error while saving HTML report: " + e.message);
    }
}

function processAlert(alerts) {
    var finalPlan = [];

    alerts.forEach((alert) => {
        if (!alert || !(alert.risk === 'High')) {
            return;
        }
        print(JSON.stringify(alert));
        var cweDetails = getCWEDetails(alert.cweid);
        print(JSON.stringify(cweDetails));
        var firstPlan = getMitigationPlan(alert, cweDetails);
        print("first " + firstPlan);
        print("\n\n");
        var secondPlan = recheck(firstPlan, cweDetails);
        print("second " + secondPlan);
        finalPlan.push(secondPlan);
    })

    return finalPlan;
}

// Function to generate report
function generateReport(alerts) {
    var reportContent = '<html><head><title>ZAP Mitigation Report</title></head><body>';
    reportContent += '<h1>Mitigation Plans</h1>';

    // time for chatgpt
    

    // Print or save the report content as needed
    print(reportContent)
    saveReport(reportContent)
}

// Main function to execute the process
function main() {
    try {
        var alerts = getZAPAlerts();
        var finalAlerts = processAlert(alerts);
        
        // generateReport(finalAlerts);
    } catch (error) {
        print('Error in main execution: ' + error);
    }
}

// Run the main function
main();