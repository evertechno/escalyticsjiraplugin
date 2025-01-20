import streamlit as st
import google.generativeai as genai
from io import BytesIO
import json
import matplotlib.pyplot as plt
import re
import nltk
from nltk.corpus import stopwords
from collections import Counter
from wordcloud import WordCloud
from fpdf import FPDF
import langdetect
import requests
from datetime import datetime

# Configure API Key securely from Streamlit's secrets
genai.configure(api_key=st.secrets["GOOGLE_API_KEY"])

# Jira credentials and API URL (store securely in Streamlit's secrets or environment variables)
JIRA_API_URL = st.secrets["JIRA_API_URL"]
JIRA_USERNAME = st.secrets["JIRA_USERNAME"]
JIRA_API_TOKEN = st.secrets["JIRA_API_TOKEN"]

# App Configuration
st.set_page_config(page_title="Escalytics", page_icon="📧", layout="wide")
st.title("⚡Escalytics by EverTech")
st.write("Extract insights, root causes, and actionable steps from emails.")

# Sidebar for Features
st.sidebar.header("Settings")
features = {
    "sentiment": st.sidebar.checkbox("Perform Sentiment Analysis"),
    "highlights": st.sidebar.checkbox("Highlight Key Phrases"),
    "response": st.sidebar.checkbox("Generate Suggested Response"),
    "wordcloud": st.sidebar.checkbox("Generate Word Cloud"),
    "grammar_check": st.sidebar.checkbox("Grammar Check"),
    "key_phrases": st.sidebar.checkbox("Extract Key Phrases"),
    "actionable_items": st.sidebar.checkbox("Extract Actionable Items"),
    "root_cause": st.sidebar.checkbox("Root Cause Detection"),
    "risk_assessment": st.sidebar.checkbox("Risk Assessment"),
    "severity_detection": st.sidebar.checkbox("Severity Detection"),
    "critical_keywords": st.sidebar.checkbox("Critical Keyword Identification"),
    "escalation_trigger": st.sidebar.checkbox("Escalation Trigger Detection"),
    "culprit_identification": st.sidebar.checkbox("Culprit Identification"),
    "email_summary": st.sidebar.checkbox("Email Summary"),
    "language_detection": st.sidebar.checkbox("Language Detection"),
    "entity_recognition": st.sidebar.checkbox("Entity Recognition"),
    "response_time_analysis": st.sidebar.checkbox("Response Time Analysis"),
    "attachment_analysis": st.sidebar.checkbox("Attachment Analysis"),
    "customer_tone_analysis": st.sidebar.checkbox("Customer Tone Analysis"),
    "department_identification": st.sidebar.checkbox("Department Identification"),
    "priority_identification": st.sidebar.checkbox("Priority Identification"),
    "urgency_assessment": st.sidebar.checkbox("Urgency Assessment"),
    "action_item_priority": st.sidebar.checkbox("Action Item Priority"),
    "deadline_detection": st.sidebar.checkbox("Deadline Detection"),
    "email_chain_analysis": st.sidebar.checkbox("Email Chain Analysis"),
    "executive_summary": st.sidebar.checkbox("Executive Summary"),
    "actionable_resolution": st.sidebar.checkbox("Actionable Resolution Detection"),
    "response_completeness": st.sidebar.checkbox("Response Completeness"),
    "agreement_identification": st.sidebar.checkbox("Agreement Identification"),
    "feedback_analysis": st.sidebar.checkbox("Feedback Analysis"),
    "threat_detection": st.sidebar.checkbox("Threat Detection"),
    "response_quality_assessment": st.sidebar.checkbox("Response Quality Assessment"),
}

# Input Email Section
email_content = st.text_area("Paste your email content here:", height=200)

MAX_EMAIL_LENGTH = 1000

# Cache the AI responses to improve performance
@st.cache_data(ttl=3600)
def get_ai_response(prompt, email_content):
    try:
        model = genai.GenerativeModel("gemini-1.5-flash")
        response = model.generate_content(prompt + email_content[:MAX_EMAIL_LENGTH])
        return response.text.strip()
    except Exception as e:
        st.error(f"Error: {e}")
        return ""

# Generate Suggested Response (for Jira Integration)
def generate_jira_response(email_content):
    return get_ai_response("Draft a professional response to this email:\n\n", email_content)

# Jira Integration: Create a comment on Jira ticket
def create_jira_comment(ticket_id, comment):
    url = f"{JIRA_API_URL}/rest/api/2/issue/{ticket_id}/comment"
    headers = {
        "Authorization": f"Basic {requests.auth._basic_auth_str(JIRA_USERNAME, JIRA_API_TOKEN)}",
        "Content-Type": "application/json"
    }
    payload = json.dumps({"body": comment})
    response = requests.post(url, headers=headers, data=payload)
    
    if response.status_code == 201:
        st.success("Comment successfully added to the Jira ticket.")
    else:
        st.error(f"Failed to add comment to Jira: {response.status_code}, {response.text}")

# Sentiment Analysis
def get_sentiment(email_content):
    positive_keywords = ["happy", "good", "great", "excellent", "love"]
    negative_keywords = ["sad", "bad", "hate", "angry", "disappointed"]
    sentiment_score = 0
    for word in email_content.split():
        if word.lower() in positive_keywords:
            sentiment_score += 1
        elif word.lower() in negative_keywords:
            sentiment_score -= 1
    return sentiment_score

# Grammar Check (basic spelling correction)
def grammar_check(text):
    corrections = {
        "recieve": "receive",
        "adress": "address",
        "teh": "the",
        "occured": "occurred"
    }
    for word, correct in corrections.items():
        text = text.replace(word, correct)
    return text

# Key Phrase Extraction
def extract_key_phrases(text):
    key_phrases = re.findall(r"\b[A-Za-z]{4,}\b", text)
    return list(set(key_phrases))  # Remove duplicates

# Export to PDF
def export_pdf(text):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.multi_cell(0, 10, text)
    return pdf.output(dest='S').encode('latin1')

# Actionable Items Extraction
def extract_actionable_items(text):
    actions = [line for line in text.split("\n") if "to" in line.lower() or "action" in line.lower()]
    return actions

# Root Cause Detection
def detect_root_cause(text):
    if "lack of communication" in text.lower():
        return "Root Cause: Lack of communication between teams."
    elif "delayed response" in text.lower():
        return "Root Cause: Delayed response from the team."
    return "Root Cause: Unknown"

# Generate insights and create Jira comment
if email_content and st.button("Generate Insights"):
    try:
        # Generate AI-like responses
        summary = get_ai_response("Summarize the email in a concise, actionable format:\n\n", email_content)
        response = generate_jira_response(email_content)
        highlights = get_ai_response("Highlight key points and actions in this email:\n\n", email_content)

        # Sentiment Analysis
        sentiment = get_sentiment(email_content)

        # Visualize Word Cloud
        wordcloud = generate_wordcloud(email_content)
        st.image(wordcloud.to_array(), caption="Generated Word Cloud")

        # Show results and Jira comment button
        st.subheader("Summary of Insights:")
        st.write(summary)

        st.subheader("Suggested Response:")
        st.write(response)

        # Jira ticket ID input
        ticket_id = st.text_input("Enter the Jira ticket ID to post a comment:")

        # If the ticket ID is provided, post the comment to Jira
        if ticket_id:
            create_jira_comment(ticket_id, response)

    except Exception as e:
        st.error(f"Error generating insights: {e}")
