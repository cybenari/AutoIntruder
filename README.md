# AutoIntruder

A BurpSuite plugin designed to help find authorization and IDOR issues by finding requests and payloads that match a pattern (like a UUID pattern) and send all variations that were found
of the the pattern in the request history.



## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
- [UseCase](#Typical Use Case)
- [Contact](#contact)

## Installation

1. Clone the repo:
    ```sh
    git clone https://github.com/cybenari/AutoIntruder.git
    ```
2. Navigate to the project directory:
    ```sh
    cd AutoIntruder
    ```
3. Build:
    ```sh
    mvn package
    ```
4. Run the project:
    
    Load the generated JAR file as a BurpSuite Extension.
    

## Usage

Step 1. Create a regex pattern you want AutoIntruder to find in the Proxy history
Step 2. Add some filter rules (Like only requests that are in scope)
Step 3. Add some payloads in the payloads tab
Step 4. Decide which requests you want to enable and which to disable
Step 5. Send the requests
Step 6. Profit

```sh
example code or command
```

## Typical Use Case
You are performing a penteration test/Bug Bounty/Research and you want to test for IDORs, but the application is BIG and there are a lot of places where the app is using UUIDs if object ids.
In such a case you can configure the parameter pattern to be a UUID Regex Pattern. Next you can add some rules to the filter and exclude the DELETE method (So you won't accidently delete anything important). 
Next you'll want AutoIntruder to automatically generate all the payloads found in the scope that match a UUID pattern (and this is where the power of this tools really comes into play).
Now in the Results tab is populated with list of requests (unsent yet) of all the combinations of requests that match the parameter pattern and the payload patterns. 
You fire up the requests and look for responses that return a 200 OK (but probably should have returned a 403). 
You go over the these 200 OK responses and find an IDOR Hurray!

## Contact
idan@cybenari.com