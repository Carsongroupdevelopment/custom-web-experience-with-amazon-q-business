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
  st.session_state.messages = [
    {"role": "assistant", "content": "How may I assist you today?"}]
  st.session_state.questions = []
  st.session_state.answers = []
  st.session_state.input = ""
  st.session_state["chat_history"] = []
  st.session_state["conversationId"] = ""
  st.session_state["parentMessageId"] = ""

def get_aws_credentials(identity_pool_id, region, id_token):
  try:




    # Step 1: Decode the ID token to get the email claim
    decoded_token = jwt.decode(id_token, options={"verify_signature": False})
    email = decoded_token.get("email")
    if not email:
      raise ValueError("Email claim is missing from the ID token")
    st.write(email)

    # Prepare tags for role assumption
    tags = [
      {"Key": "Email", "Value": email},
      {"Key": "FederatedProvider", "Value": "arn:aws:iam::703671919012:oidc-provider/cognito-idp.us-west-2.amazonaws.com/us-west-2_oB53gulKJ"}
    ]

    # Step 2: Get the Identity ID from Cognito
    cognito_identity_client = boto3.client("cognito-identity", region_name=region)
    response = cognito_identity_client.get_id(
        IdentityPoolId=identity_pool_id,
        Logins={"cognito-idp.us-west-2.amazonaws.com/us-west-2_oB53gulKJ": id_token}
    )
    identity_id = response["IdentityId"]

    # Step 3: Get AWS credentials for the Identity ID
    credentials_response = cognito_identity_client.get_credentials_for_identity(
        IdentityId=identity_id,
        Logins={"cognito-idp.us-west-2.amazonaws.com/us-west-2_oB53gulKJ": id_token}
    )
    credentials = credentials_response["Credentials"]
    st.write(credentials)

    # Step 4: Assume the role using the temporary credentials
    session = boto3.Session(
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretKey"],
        aws_session_token=credentials["SessionToken"],
        region_name=region
    )
    sts_client = session.client("sts")
    assumed_role = sts_client.assume_role(
        RoleArn="arn:aws:iam::703671919012:role/steve_ai_cognito_identity_pool_role",
        RoleSessionName="session_name",
        Tags=tags
    )
    st.write("Assumed Role")

    # Return the credentials from the assumed role




    # Step 1: Decode the ID token to verify claims if needed
    # decoded_token = jwt.decode(id_token, options={"verify_signature": False})
    # email = decoded_token.get("email")
    # if not email:
    #   raise ValueError("Email claim is missing from the ID token")
    #
    # tags = [
    # {"Key": "Email", "Value": email}
    # ]
    #
    # # Step 2: Assume the role using the ID token
    # sts_client = boto3.client("sts", region_name=region)
    # assumed_role = sts_client.assume_role_with_web_identity(
    #     RoleArn="arn:aws:iam::703671919012:role/steve_ai_cognito_identity_pool_role",
    #     RoleSessionName="session_name",
    #     WebIdentityToken=id_token,
    # )

    return assumed_role["Credentials"]
  except Exception as e:
    st.error(f"Failed to retrieve AWS credentials: {e}")
    return None

def create_aws_session(aws_credentials):
  try:
    # Create an initial session with the provided AWS credentials
    session = boto3.Session(
        aws_access_key_id=aws_credentials["AccessKeyId"],
        aws_secret_access_key=aws_credentials["SecretAccessKey"],
        aws_session_token=aws_credentials["SessionToken"],
        region_name="us-west-2"
    )
    return session
  except Exception as e:
    print(f"Error creating AWS session: {e}")
    return None



# Function to call Amazon Q (or any other AWS service) using the credentials
def call_amazon_q_with_credentials(aws_credentials):

  st.write(aws_credentials)
  session = create_aws_session(aws_credentials)

  if session:
    # Initialize a Q client using the session
    q_client = session.client("qbusiness")
    # Call to Amazon Q with the token and AWS credentials
    response = utils.get_queue_chain(
        prompt,
        st.session_state["conversationId"],
        st.session_state["parentMessageId"],
        q_client
    )

    # You can use the response from Amazon Q (based on the response format)
    return response

  if session is None:
    return None


oauth2 = utils.configure_oauth_component()
if "token" not in st.session_state:
  # Show authorize button if no token in session
  redirect_uri = f"https://{utils.OAUTH_CONFIG['ExternalDns']}/component/streamlit_oauth.authorize_button/index.html"
  result = oauth2.authorize_button("Connect with Cognito", scope="openid email",
                                   pkce="S256", redirect_uri=redirect_uri)
  if result and "token" in result:
    # Save token in session state after successful authorization
    st.session_state.token = result.get("token")
    st.rerun()
else:
  token = st.session_state["token"]
  refresh_token = token["refresh_token"]  # Save long-lived refresh_token
  user_email = \
  jwt.decode(token["id_token"], options={"verify_signature": False})["email"]

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

      aws_session = create_aws_session(aws_credentials)
      if aws_session:
        st.session_state.aws_session = aws_session
      else:
        st.error("Unable to create AWS session with tags.")
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

  sts_client = boto3.client('sts')
  caller_identity = sts_client.get_caller_identity()
  st.components.v1.html(
      f"""
                <script>
                    console.log("Caller Identity AFTER get creds", "{caller_identity}");
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
    st.session_state.messages = [
      {"role": "assistant", "content": "How can I help you?"}]
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
        st.success("Calling Amazon Q with credentials...")
        response = call_amazon_q_with_credentials(
            st.session_state.aws_credentials
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

    st.session_state.messages.append(
        {"role": "assistant", "content": full_response})
    feedback = streamlit_feedback(
        feedback_type="thumbs",
        optional_text_label="[Optional] Please provide an explanation",
    )
