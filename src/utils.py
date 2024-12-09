import datetime
import logging
import os

import boto3
import jwt
import streamlit as st
import urllib3
from streamlit_oauth import OAuth2Component

logger = logging.getLogger()

# Read the configuration file
APPCONFIG_APP_NAME = os.environ["APPCONFIG_APP_NAME"]
APPCONFIG_ENV_NAME = os.environ["APPCONFIG_ENV_NAME"]
APPCONFIG_CONF_NAME = os.environ["APPCONFIG_CONF_NAME"]
AMAZON_Q_APP_ID = None
IAM_ROLE = None
REGION = None
IDC_APPLICATION_ID = None
OAUTH_CONFIG = {}


def retrieve_config_from_agent():
    """
    Retrieve the configuration from the agent
    """
    global IAM_ROLE, REGION, IDC_APPLICATION_ID, AMAZON_Q_APP_ID, OAUTH_CONFIG
    config = urllib3.request(
        "GET",
        f"http://localhost:2772/applications/{APPCONFIG_APP_NAME}/environments/{APPCONFIG_ENV_NAME}/configurations/{APPCONFIG_CONF_NAME}",
    ).json()
    IAM_ROLE = config["IamRoleArn"]
    REGION = config["Region"]
    IDC_APPLICATION_ID = config["IdcApplicationArn"]
    AMAZON_Q_APP_ID = config["AmazonQAppId"]
    OAUTH_CONFIG = config["OAuthConfig"]


def configure_oauth_component():
    """
    Configure the OAuth2 component for Cognito
    """
    cognito_domain = OAUTH_CONFIG["CognitoDomain"]
    authorize_url = f"https://{cognito_domain}/oauth2/authorize"
    token_url = f"https://{cognito_domain}/oauth2/token"
    refresh_token_url = f"https://{cognito_domain}/oauth2/token"
    revoke_token_url = f"https://{cognito_domain}/oauth2/revoke"
    client_id = OAUTH_CONFIG["ClientId"]
    return OAuth2Component(
        client_id, None, authorize_url, token_url, refresh_token_url, revoke_token_url
    )
# This code invoke chat_sync api and format the response for UI
def get_queue_chain(
    prompt_input, conversation_id, parent_message_id, q_client
):
    """"
    This method is used to get the answer from the queue chain.
    """
    if conversation_id != "":
        answer = q_client.chat_sync(
            applicationId=AMAZON_Q_APP_ID,
            userMessage=prompt_input,
            conversationId=conversation_id,
            parentMessageId=parent_message_id,
        )
    else:
        answer = q_client.chat_sync(
            applicationId=AMAZON_Q_APP_ID, userMessage=prompt_input
        )

    system_message = answer.get("systemMessage", "")
    conversation_id = answer.get("conversationId", "")
    parent_message_id = answer.get("systemMessageId", "")
    result = {
        "answer": system_message,
        "conversationId": conversation_id,
        "parentMessageId": parent_message_id,
    }

    if answer.get("sourceAttributions"):
        attributions = answer["sourceAttributions"]
        valid_attributions = []

        # Generate the answer references extracting citation number,
        # the document title, and if present, the document url
        for attr in attributions:
            title = attr.get("title", "")
            url = attr.get("url", "")
            citation_number = attr.get("citationNumber", "")
            attribution_text = []
            if citation_number:
                attribution_text.append(f"[{citation_number}]")
            if title:
                attribution_text.append(f"Title: {title}")
            if url:
                attribution_text.append(f", URL: {url}")

            valid_attributions.append("".join(attribution_text))

        concatenated_attributions = "\n\n".join(valid_attributions)
        result["references"] = concatenated_attributions

        # Process the citation numbers and insert them into the system message
        citations = {}
        for attr in answer["sourceAttributions"]:
            for segment in attr["textMessageSegments"]:
                citations[segment["endOffset"]] = attr["citationNumber"]
        offset_citations = sorted(citations.items(), key=lambda x: x[0])
        modified_message = ""
        prev_offset = 0

        for offset, citation_number in offset_citations:
            modified_message += (
                system_message[prev_offset:offset] + f"[{citation_number}]"
            )
            prev_offset = offset

        modified_message += system_message[prev_offset:]
        result["answer"] = modified_message

    return result
