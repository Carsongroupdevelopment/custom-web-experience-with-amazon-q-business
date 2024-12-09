from datetime import datetime, timedelta, timezone
import jwt
import streamlit as st
import boto3
import utils
from streamlit_feedback import streamlit_feedback

UTC = timezone.utc

# Init configuration
utils.retrieve_config_from_agent()
if "aws_credentials" not in st.session_state:
    st.session_state.aws_credentials = None

st.set_page_config(page_title="Amazon Q Business Custom UI")  # HTML title
st.title("Amazon Q Business Custom UI")  # Page title

# Define a function to clear the chat history
def clear_chat_history():
    st.session_state.messages = [{"role": "assistant", "content": "How may I assist you today?"}]
    st.session_state.questions = []
    st.session_state.answers = []
    st.session_state.input = ""
    st.session_state["chat_history"] = []
    st.session_state["conversationId"] = ""
    st.session_state["parentMessageId"] = ""

# Function to retrieve AWS credentials from Identity Pool
def get_aws_credentials(identity_pool_id, region, id_token):
    cognito_identity_client = boto3.client("cognito-identity", region_name=region)
    try:
        # Step 1: Get the Identity ID
        response = cognito_identity_client.get_id(
            IdentityPoolId=identity_pool_id,
            Logins={"cognito-idp.us-west-2.amazonaws.com/us-west-2_oB53gulKJ": id_token}
        )
        identity_id = response["IdentityId"]

        # Step 2: Get AWS credentials for the Identity ID
        credentials_response = cognito_identity_client.get_credentials_for_identity(
            IdentityId=identity_id,
            Logins={"cognito-idp.us-west-2.amazonaws.com/us-west-2_oB53gulKJ": id_token}
        )

        st.write(st.session_state.aws_credentials)
        return credentials_response["Credentials"]
    except Exception as e:
        st.error(f"Failed to retrieve AWS credentials: {e}")
        return None

# Function to create a boto3 session with the retrieved AWS credentials
def create_aws_session(aws_credentials):
    try:
        session = boto3.Session(
            aws_access_key_id=aws_credentials["AccessKeyId"],
            aws_secret_access_key=aws_credentials["SecretKey"],
            aws_session_token=aws_credentials["SessionToken"],
            region_name="us-west-2"
        )
        return session
    except Exception:
        st.error("AWS credentials are missing or invalid.")
        return None

# Function to call Amazon Q (or any other AWS service) using the credentials
def call_amazon_q_with_credentials(aws_credentials, token):
    session = create_aws_session(aws_credentials)

    sts_client = boto3.client('sts')
    caller_identity = sts_client.get_caller_identity()
    st.components.v1.html(
        f"""
                <script>
                    console.log("Caller Identity", "{caller_identity}");
                </script>
                """,
        height=0,
    )
    if session is None:
        return None

    # Example: Initialize a Q client using the session
    q_client = session.client('qbusiness')
    st.components.v1.html(
        f"""
            <script>
                console.log("Q client", "{q_client}");
            </script>
            """,
        height=0,
    )
    # Call to Amazon Q with the token and AWS credentials
    response = utils.get_queue_chain(
        prompt,
        st.session_state["conversationId"],
        st.session_state["parentMessageId"],
        q_client
    )

    # You can use the response from Amazon Q (based on the response format)
    return response

oauth2 = utils.configure_oauth_component()
if "token" not in st.session_state:
    # Show authorize button if no token in session
    redirect_uri = f"https://{utils.OAUTH_CONFIG['ExternalDns']}/component/streamlit_oauth.authorize_button/index.html"
    result = oauth2.authorize_button("Connect with Cognito", scope="openid", pkce="S256", redirect_uri=redirect_uri)
    if result and "token" in result:
        # Save token in session state after successful authorization
        st.session_state.token = result.get("token")
        st.rerun()
else:
    token = st.session_state["token"]
    refresh_token = token["refresh_token"]  # Save long-lived refresh_token
    user_email = jwt.decode(token["id_token"], options={"verify_signature": False})["email"]

    if st.button("Refresh Cognito Token"):
        # Refresh token if expired or on button click
        token = oauth2.refresh_token(token, force=True)
        token["refresh_token"] = refresh_token  # Ensure refresh_token remains
        st.session_state.token = token
        st.rerun()

    # Retrieve AWS credentials using the Cognito Identity Pool
    if st.session_state.aws_credentials is None:
        identity_pool_id = "us-west-2:a1448413-7bb0-4b75-bd90-04ce945f405a"  # Replace with your Cognito Identity Pool ID
        region = "us-west-2"  # Replace with your AWS region
        id_token = st.session_state.token["id_token"]
        aws_credentials = get_aws_credentials(identity_pool_id, region, id_token)
        if aws_credentials:
            st.session_state.aws_credentials = aws_credentials
            st.write(st.session_state.aws_credentials)
            st.success("AWS credentials successfully retrieved!")
        else:
            st.error("Unable to retrieve AWS credentials.")

    # Automatically log the JWT token to the browser console
    if "id_token" in st.session_state["token"]:
        raw_token = st.session_state["token"]["id_token"]
        st.components.v1.html(
            f"""
            <script>
                console.log("JWT Token:", "{raw_token}");
            </script>
            """,
            height=0,
        )

    col1, col2 = st.columns([1, 1])
    with col1:
        st.write("Welcome: ", user_email)
    with col2:
        st.button("Clear Chat History", on_click=clear_chat_history)

    # Initialize session state variables for chat
    if "messages" not in st.session_state:
        st.session_state.messages = [{"role": "assistant", "content": "How can I help you?"}]
    if "conversationId" not in st.session_state:
        st.session_state["conversationId"] = ""
    if "parentMessageId" not in st.session_state:
        st.session_state["parentMessageId"] = ""
    if "chat_history" not in st.session_state:
        st.session_state["chat_history"] = []
    if "questions" not in st.session_state:
        st.session_state.questions = []
    if "answers" not in st.session_state:
        st.session_state.answers = []
    if "input" not in st.session_state:
        st.session_state.input = ""

    # Display chat messages
    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.write(message["content"])

    # User-provided prompt
    if prompt := st.chat_input():
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.write(prompt)

    # Generate a response from Amazon Q for the latest user input
    if st.session_state.messages[-1]["role"] != "assistant":
        with st.chat_message("assistant"):
            with st.spinner("Thinking..."):
                placeholder = st.empty()
                response = call_amazon_q_with_credentials(
                    st.session_state.aws_credentials,
                    st.session_state.token
                )
                if response:
                    if "references" in response:
                        full_response = f"""{response["answer"]}\n\n---\n{response["references"]}"""
                    else:
                        full_response = f"""{response["answer"]}\n\n---\nNo sources"""

                    st.session_state["conversationId"] = response["conversationId"]
                    st.session_state["parentMessageId"] = response["parentMessageId"]
                else:
                    full_response = "Sorry, there was an error retrieving the response."

                placeholder.markdown(full_response)


        st.session_state.messages.append({"role": "assistant", "content": full_response})
        feedback = streamlit_feedback(
            feedback_type="thumbs",
            optional_text_label="[Optional] Please provide an explanation",
        )
