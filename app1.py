import numpy as np
from tensorflow.keras.models import load_model
import streamlit as st
import hashlib

# Load the final prediction model
final_model = load_model('quantum_nn_model.h5')

# Function to process the uploaded transaction file
def process_magnitude_file(file_content):
    magnitudes = np.fromstring(file_content, sep=" ")
    return magnitudes.reshape(1, -1)

# In-memory database of users for simplicity
users_db = {
    'admin': {
        'name': 'Admin User',
        'password': hashlib.sha256('admin_password'.encode()).hexdigest()
    }
}

# Authentication function
def authenticate(username, password):
    if username in users_db:
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        return hashed_password == users_db[username]['password']
    return False

# Streamlit interface
st.title("Fraud Detection System")

# Check if the user is authenticated
if 'authenticated' not in st.session_state:
    st.session_state['authenticated'] = False

# If the user is authenticated, show the upload page
if st.session_state['authenticated']:
    st.write(f'Welcome {st.session_state["username"]}')
    
    # Upload magnitude data file
    uploaded_file = st.file_uploader("Upload a magnitude data file", type="txt")

    if uploaded_file is not None:
        file_content = uploaded_file.read().decode("utf-8")
        magnitudes = process_magnitude_file(file_content)
        
        # Predict using the final model
        final_prediction = final_model.predict(magnitudes)
        final_prediction_class = (final_prediction > 0.5).astype(int)
        
        # Display prediction result
        st.subheader("Prediction Result")
        st.write(f"The model predicts that the transaction is {'fraudulent' if final_prediction_class[0] == 1 else 'not fraudulent'}.")
else:
    # Login and Sign-up pages
    page = st.sidebar.selectbox("Choose a page", ["Login", "Sign up"])

    if page == "Login":
        st.subheader("Login")
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        login_button = st.button("Login")
        
        if login_button:
            if authenticate(username, password):
                st.session_state['authenticated'] = True
                st.session_state['username'] = username
                st.success("Login successful")
                st.experimental_rerun()
            else:
                st.error("Invalid username or password")
                
    elif page == "Sign up":
        st.subheader("Sign up")
        new_username = st.text_input("New Username")
        new_name = st.text_input("Name")
        new_password = st.text_input("Password", type="password")
        confirm_password = st.text_input("Confirm Password", type="password")
        signup_button = st.button("Sign up")
        
        if signup_button:
            if new_password == confirm_password and new_password != '':
                if new_username not in users_db:
                    hashed_password = hashlib.sha256(new_password.encode()).hexdigest()
                    users_db[new_username] = {'name': new_name, 'password': hashed_password}
                    st.success("Account created successfully! Please login.")
                else:
                    st.error("Username already exists")
            else:
                st.error("Passwords do not match or are empty")
