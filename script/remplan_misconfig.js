// Configuration
var zapUrl = 'http://localhost:8080'; // Adjust if ZAP is running elsewhere
var zapApiKey = ''; // Replace with actual ZAP API key
var cweApiUrl = 'https://cwe-api.mitre.org/api/v1/cwe/weakness/';
var perplexityApiUrl = 'https://api.perplexity.ai/chat/completions';
var perplexityApiKey = ''; // Replace with actual Perplexity API key

// Specify the tech stack of the target web application
var techStack = "Node.js, Express, MySQL";
// Specify the report file path
var outputPath = `C:\\Users\\<user>\\Desktop\\report_${Date.now()}.md`

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
                + " with tech stack: " + techStack
                + " Provide vulnerability explanation, How it works, Example of common situation when this vulnerability occur,"
                + " Consequences, Evidence from the alert (add more context if needed, including the URL of alert as evidence as well), Mitigation strategies ("
                + "Provide practical and context-specific mitigation strategies that can mitigate the vulnerability of the detected evidence."
                + " You might have many strategies, if so please write it in list format. You must provide practical code example based on the context of evidence and tech stack (NodeJS, Express, MySQL). "
            }
        ]
    };

    var requestBody = JSON.stringify(requestData);
    
    try {
        var uri = new URI(perplexityApiUrl);
        var request = new PostMethod(uri.toString());
        request.setRequestEntity(new StringRequestEntity(requestBody, "application/json", "UTF-8"));
        request.addRequestHeader("Authorization", "Bearer " + perplexityApiKey);
    
        client.executeMethod(request);
        var response = request.getResponseBodyAsString();
        return JSON.parse(response).choices[0].message.content;

    } catch (e) {
        print("Error fetching mitigation plan: " + e);
        return null;
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
          response +
          " with the provided CWE information: " +
          cwe +
          " If the provided plan is valid, send back the same plan content, "
          + "else revise it to correspond to the provided CWE and sent it back in format same as the provided plan."
          + "The tech stack is the same: " + techStack,
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
    return response;
  } catch (e) {
    print("Error fetching mitigation plan: " + e);
    return null;
  }
}

function saveReport(reportContent) {
    // Import Java file handling classes
    var FileWriter = Java.type("java.io.FileWriter");
    var BufferedWriter = Java.type("java.io.BufferedWriter");

    try {
        // Create a writer to save the content
        var writer = new BufferedWriter(new FileWriter(outputPath));
        
        // Write the content to the file
        writer.write(reportContent);
        
        // Close the writer
        writer.close();
        print("Report successfully saved to: " + outputPath);
    } catch (e) {
        print("Error while saving report: " + e.message);
    }
}

function processAlert(alerts) {
    var finalPlan = [];

    alerts.forEach((alert) => {
        if (!alert || !(alert.risk === "Medium" && (alert.tags.OWASP_2017_A06 !== undefined || alert.tags.OWASP_2021_A05 !== undefined))) {
            return;
        }

        var cweDetails = getCWEDetails(alert.cweid);
        var firstPlan = getMitigationPlan(alert, cweDetails);
        var secondPlan = recheck(firstPlan, cweDetails);
        finalPlan.push([secondPlan, alert]);
        // finalPlan.push(firstPlan);
    })

    return finalPlan;
}

// Function to generate report
function generateReport(responses) {
    var markdownReport = `
# Mitigation Report

    `;
    
    responses.forEach((response) => {
        // Parse the JSON response
        var plan = response[0];
        var alert = response[1];
        var responseObject = JSON.parse(plan);

        // Extract relevant information
        var id = responseObject.id;
        var model = responseObject.model;
        var choices = responseObject.choices[0].message.content; // Get content from the first choice
        var citations = responseObject.citations.join('\n'); // Join citations into a string

        markdownReport += `
## Mitigation Plan: ${alert.alert}

**ID:** ${id}  
**Model:** ${model}

${choices}

## Citations
${citations}
`
        })
    
    // Print or save the report content as needed
    print(markdownReport)
    saveReport(markdownReport)
}

function main() {
    try {
        var alerts = getZAPAlerts();
        var finalAlerts = processAlert(alerts);
        generateReport(finalAlerts);

    } catch (error) {
        print('Error in main execution: ' + error);
    }
}

main();