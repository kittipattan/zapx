/**
 * Scans a specific parameter in an HTTP message.
 * The scan function will typically be called for every parameter in every URL and Form for every page.
 *
 * @param as - the ActiveScan parent object that will do all the core interface tasks
 *     (i.e.: sending and receiving messages, providing access to Strength and Threshold settings,
 *     raising alerts, etc.). This is an ScriptsActiveScanner object.
 * @param msg - the HTTP Message being scanned. This is an HttpMessage object.
 * @param {string} param - the name of the parameter being manipulated for this test/scan.
 * @param {string} value - the original parameter value.
 */

const TimeUnit = Java.type("java.util.concurrent.TimeUnit");

function scan(as, msg, param, value) {
  // Debugging can be done using println like this
  print(
    "scan called for url=" +
      msg.getRequestHeader().getURI().toString() +
      " param=" +
      param +
      " value=" +
      value
  );

  // Copy requests before reusing them
  msg = msg.cloneRequest();

  // setParam (message, parameterName, newValue)
  as.setParam(msg, param, "Your attack");

  // sendAndReceive(msg, followRedirect, handleAntiCSRFtoken)
  as.sendAndReceive(msg, false, false);

  // Test the response here, and make other requests as required
  if (true) {
    // Change to a test which detects the vulnerability
    // risk: 0: info, 1: low, 2: medium, 3: high
    // confidence: 0: falsePositive, 1: low, 2: medium, 3: high, 4: confirmed
    try {
      // Ensure we only process 200 responses with content type 'text/html'
      if (
        msg.getResponseHeader().getStatusCode() === 200 &&
        msg.getResponseHeader().getHeader("Content-Type") &&
        msg
          .getResponseHeader()
          .getHeader("Content-Type")
          .toString()
          .toLowerCase()
          .contains("text/html")
      ) {
        // Configuration
        const numberOfRequests = 1000; // Number of requests to send
        const requestDelay = 0; // Delay between requests in milliseconds
        const responseTimes = [];
        let captchaDetected = false;
        let rateLimiting = false;

        for (let i = 0; i < numberOfRequests; i++) {
          // Send and receive the request
          as.sendAndReceive(msg, false, false);

          // Record response time
          const responseTime = msg.getTimeElapsedMillis();
          responseTimes.push(responseTime);

          // Check for CAPTCHA in the response body
          if (
            msg.getResponseBody().toString().toLowerCase().contains("captcha")
          ) {
            captchaDetected = true;
          }

          const statusCode = msg.getResponseHeader().getStatusCode();
          // Check for response status code
          if (
            statusCode === 429 ||
            statusCode === 403 ||
            statusCode === 503 ||
            statusCode === 401
          ) {
            rateLimiting = true;
          }

          // Output the request status for debugging
          print(
            `Request ${i + 1}/${numberOfRequests}: Status ${msg
              .getResponseHeader()
              .getStatusCode()}, Response Time ${responseTime} ms`
          );

          // Add delay between requests
          if (requestDelay > 0) {
            TimeUnit.MILLISECONDS.sleep(requestDelay);
          }
        }

        // Analyze the absence of defenses
        analyzeDefenseAbsence(
          as,
          msg,
          responseTimes,
          captchaDetected,
          rateLimiting
        );
      }
    } catch (e) {
      print(`Error during scan: ${e}`);
    }
  }
}

function analyzeDefenseAbsence(
  as,
  msg,
  responseTimes,
  captchaDetected,
  rateLimiting
) {
  // Analyze rate-limiting
  if (responseTimes.length < 2) {
    print("Not enough responses to analyze rate-limiting.");
    return;
  }

  const initialResponseTime = responseTimes[0] !== 0 ? responseTimes[0] : 1;

  let maxResponseTime = initialResponseTime;
  responseTimes.forEach(function (t) {
    if (maxResponseTime < t) maxResponseTime = t;
  });

  print(`Initial Response Time: ${initialResponseTime} ms`);
  print(`Maximum Response Time: ${maxResponseTime} ms`);

  // Check for rate-limiting
  if (maxResponseTime <= initialResponseTime * 20 && !rateLimiting) {
    raiseAlert(
      as,
      msg,
      "Lack of Rate-Limiting",
      "The application does not implement rate-limiting to prevent excessive requests.",
      `Response Time: ${maxResponseTime} ms`,
      msg.getRequestHeader().getURI().toString()
    );
  }

  // Check for absence of CAPTCHA
  if (!captchaDetected) {
    raiseAlert(
      as,
      msg,
      "Lack of CAPTCHA",
      "The application does not implement CAPTCHA challenges, making it vulnerable to automated attacks.",
      "No CAPTCHA detected in responses.",
      msg.getRequestHeader().getURI().toString()
    );
  }
}

var Alert = Java.type("org.parosproxy.paros.core.scanner.Alert");
var Control = Java.type("org.parosproxy.paros.control.Control");
var HttpMessage = Java.type("org.parosproxy.paros.network.HttpMessage");

function raiseAlert(as, msg, name, description, evidence, uri) {
  // Raise an alert
  print(`Raising alert: ${name}`);
  as.newAlert()
    .setRisk(2)
    .setConfidence(2)
    .setName(name)
    .setParam("")
    .setAttack("")
    .setEvidence(evidence)
    .setCweId(307)
    .setWascId(15)
    .setMessage(msg)
    .raise();
}
