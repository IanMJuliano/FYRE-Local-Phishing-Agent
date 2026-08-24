# FYRE-Local-Phishing-Agent
This is an AI Agent that runs directly on your computer with Ollama. It uses google API to connect to your email and read over emails, classifying each as safe or dangerous. If the agent thinks the email is dangerous and is 90% or more confident, it will respond with the scammer and engage in guided conversation with them with memory.


HOW TO USE:

Install Python dependacies: 
  - pip install ollama google-auth google-auth-oauthlib google-api-python-client
    
Download Ollama:
  - Install Ollama on your computer. It must be running in the background for this to work
  - The current model uses llama3:8b and Qwen3.5:35b. These models worked on a computer with 32gb RAM. You are able to change the models used in               ga_final.py.
  - To install, run
    - ollama pull llama3:8b
    - ollama pull qwen3.5:35b-a3b
  - Use Google API:
      - Create a Google Cloud project and enable the Gmail API.
      - Create OAuth credentials for a Desktop application and download the credentials file.
      - Rename the downloaded file to: credentials.json
      - Place it inside the same folder as: ga_final.py, gmail_auth.py
      - Do not share your credentials.json anywhere.
   - Authenticate Email:
      - The first time the program runs, gmail_auth.py will look for token.json
      - if one does not exist, it will open Google's OAuth login flow using credentials.json. After authentication, it will create token.json so the             account can be authenticated on later runs.
      - Both credentials.json and token.json should remain private.
    - Starting the agent
      - Once everything is setup, open ga_final.py and in your terminal run python ga_final.py
      - The agent runs on a loop reading incoming emails every 5 seconds, so from there you can leave your computer running.
      - To stop the agent at any time, use CTRL + C
    
Enjoy!
