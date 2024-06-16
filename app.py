import streamlit as st
import pandas as pd
import joblib
import sqlite3
import matplotlib.pyplot as plt
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import LabelEncoder
from PIL import Image

# Load the trained models and other necessary objects
rf_clf = joblib.load('rf_clf.pkl')
svm_clf = joblib.load('svm_clf.pkl')
voting_clf = joblib.load('voting_clf.pkl')
label_encoder = joblib.load('label_encoder.pkl')
num_imputer = joblib.load('num_imputer.pkl')
attack_mapping = joblib.load('attack_mapping.pkl')

# Load the classification reports
rf_report = joblib.load('rf_report.pkl')
svm_report = joblib.load('svm_report.pkl')
voting_report = joblib.load('voting_report.pkl')

# Column names for the NSL-KDD dataset
full_feature_set = ["duration", "protocol_type", "service", "flag", "src_bytes",
                    "dst_bytes", "land", "wrong_fragment", "urgent", "hot", "num_failed_logins",
                    "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root",
                    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
                    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
                    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
                    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
                    "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
                    "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
                    "dst_host_rerror_rate", "dst_host_srv_rerror_rate"]

input_features = ["duration", "protocol_type", "service", "flag", "src_bytes"]

# ColumnTransformer preprocessing object
categorical_features = ["protocol_type", "service", "flag"]

# Function to predict category and type of attack based on the selected model
def predict_category_and_attack(test_df, model_choice):
    if model_choice == "Random Forest":
        y_new = rf_clf.predict(test_df)
    elif model_choice == "Support Vector Machine":
        y_new = svm_clf.predict(test_df)
    elif model_choice == "Ensembling":
        y_new = voting_clf.predict(test_df)
    
    predicted_category = label_encoder.inverse_transform(y_new)[0]
    
    if predicted_category == 'normal':
        return "Normal", None
    else:
        attack_type = attack_mapping.get(predicted_category, "Unknown")
        return "Attack", attack_type

# Function to evaluate model metrics and display confusion matrix
def evaluate_model_metrics(y_pred, model_name):
    # Save plot to a temporary image file
    if model_name == "Random Forest":
        temp_image = "random_forest_confusion_matrix.png"
    elif model_name == "Support Vector Machine":
        temp_image = "support_vector_machine_confusion_matrix.png"
    elif model_name == "Ensembling":
        temp_image = "ensembling_confusion_matrix.png"

    # Display the image using PIL
    image = Image.open(temp_image)
    st.image(image, caption=f"{model_name} Confusion Matrix", use_column_width=True)    

def show_predict_page():
    st.markdown(
        """
        <style>
        .full-app-container {
            background: linear-gradient(to right, #780206, #061161); 
            width: 100%;
            height: 100%;
            position: fixed;
            top: 0;
            left: 0;
            overflow: auto;
        }
        header {
            background: linear-gradient(to right, #780206, #061161) !important;
        }
        .css-1a32fsj.edgvbvh10 {
            background-color: #044455 !important;
            color: white !important;
        }
        .predict_button {
            width: 200px;
            height: 60px;
            font-size: 20px;
        }
        </style>
        """,
        unsafe_allow_html=True
    )
    st.markdown('<div class="full-app-container">', unsafe_allow_html=True)

show_predict_page()

# Streamlit UI for user input and prediction
def input():
    st.title("Intrusion Detection System Prediction")

    model_choice = st.selectbox("Choose a machine learning model", ["Random Forest", "Support Vector Machine", "Ensembling"])

    duration = st.number_input("Duration", min_value=0, max_value=100000, value=0)
    protocol = st.selectbox("Protocol Type", ["tcp", "udp", "icmp"])
    service = st.selectbox("Service", ["http", "smtp", "ftp", "other"])
    flag = st.selectbox("Flag", ["SF", "S1", "REJ", "other"])
    src_bytes = st.number_input("Source Bytes", min_value=0, max_value=100000, value=0)

    if st.button('Predict'):
        test = [duration, protocol, service, flag, src_bytes]
        test_df = pd.DataFrame([test], columns=input_features)

        # Ensure columns are in the correct order
        full_test_df = pd.DataFrame(columns=full_feature_set)
        full_test_df.loc[0, input_features] = test_df.loc[0, input_features]

        # Impute the numerical values
        numerical_cols = full_test_df.columns.difference(categorical_features)
        full_test_df[numerical_cols] = num_imputer.transform(full_test_df[numerical_cols])

        # Ensure columns are in the correct order after imputation
        full_test_df = full_test_df[full_feature_set]

        # Debug: Print the full_test_df to verify values
        st.write("Processed Test Data")
        st.dataframe(full_test_df)

        # Generate predictions
        if model_choice == "Random Forest":
            y_pred = rf_clf.predict(full_test_df)
        elif model_choice == "Support Vector Machine":
            y_pred = svm_clf.predict(full_test_df)
        elif model_choice == "Ensembling":
            y_pred = voting_clf.predict(full_test_df)

        # Display predicted category and attack type
        predicted_category, attack_type = predict_category_and_attack(full_test_df, model_choice)
        st.write(f"Predicted Category: {predicted_category}")
        if attack_type:
            st.write(f"Type of Attack: {attack_type}")

        # Save user input and predicted results to SQLite database
        save_to_database(test, predicted_category, attack_type)

        # Evaluate model metrics and display confusion matrix
        evaluate_model_metrics(y_pred, model_choice)

        # Display the classification report
        if model_choice == "Random Forest":
            st.write("### Random Forest Classification Report")
            st.json(rf_report)
        elif model_choice == "Support Vector Machine":
            st.write("### Support Vector Machine Classification Report")
            st.json(svm_report)
        elif model_choice == "Ensembling":
            st.write("### Ensembling Classification Report")
            st.json(voting_report)

def save_to_database(inputs, predicted_category, attack_type):
    conn = sqlite3.connect('predictions.db')
    c = conn.cursor()

    # Create table if not exists
    c.execute('''CREATE TABLE IF NOT EXISTS predictions
                 (duration REAL, protocol TEXT, service TEXT, flag TEXT, src_bytes REAL, predicted_category TEXT, attack_type TEXT)''')

    # Insert a row of data
    c.execute("INSERT INTO predictions VALUES (?, ?, ?, ?, ?, ?, ?)", (*inputs, predicted_category, attack_type))

    # Commit changes and close connection
    conn.commit()
    conn.close()

input()

st.markdown('</div>', unsafe_allow_html=True)
