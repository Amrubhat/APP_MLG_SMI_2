# import streamlit as st
# import pandas as pd
# import joblib
# from sklearn.impute import SimpleImputer

# # Load the trained models and other necessary objects
# rf_clf = joblib.load('rf_clf.pkl')
# svm_clf = joblib.load('svm_clf.pkl')
# voting_clf = joblib.load('voting_clf.pkl')
# label_encoder = joblib.load('label_encoder.pkl')
# num_imputer = joblib.load('num_imputer.pkl')

# # Column names for the NSL-KDD dataset
# full_feature_set = ["duration", "protocol_type", "service", "flag", "src_bytes",
#                     "dst_bytes", "land", "wrong_fragment", "urgent", "hot", "num_failed_logins",
#                     "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root",
#                     "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
#                     "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
#                     "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
#                     "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
#                     "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
#                     "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
#                     "dst_host_rerror_rate", "dst_host_srv_rerror_rate"]

# input_features = ["duration", "protocol_type", "service", "flag", "src_bytes"]

# # ColumnTransformer preprocessing object
# categorical_features = ["protocol_type", "service", "flag"]

# def show_predict_page():
#     st.markdown(
#         """
#         <style>
#         .full-app-container {
#             background: linear-gradient(to right, #64469a, #3b0234); 
#             width: 100%;
#             height: 100%;
#             position: fixed;
#             top: 0;
#             left: 0;
#             overflow: auto;
#         }
#         header {
#             background: linear-gradient(to right, #64469a, #3b0234) !important;
#         }
#         .css-1a32fsj.edgvbvh10 {
#             background-color: #044455 !important;
#             color: white !important;
#         }
#         .predict_button {
#             width: 200px;
#             height: 60px;
#             font-size: 20px;
#         }
#         </style>
#         """,
#         unsafe_allow_html=True
#     )
#     st.markdown('<div class="full-app-container">', unsafe_allow_html=True)

# show_predict_page()

# def predict_category(test_df, model_choice):
#     if model_choice == "Random Forest":
#         y_new = rf_clf.predict(test_df)
#     elif model_choice == "Support Vector Machine":
#         y_new = svm_clf.predict(test_df)
#     elif model_choice == "Ensembling":
#         y_new = voting_clf.predict(test_df)
    
#     return label_encoder.inverse_transform(y_new)[0]

# def input():
#     st.title("Intrusion Detection System Prediction")

#     model_choice = st.selectbox("Choose a machine learning model", ["Random Forest", "Support Vector Machine", "Ensembling"])

#     duration = st.number_input("Duration", min_value=0, max_value=100000, value=0)
#     protocol = st.selectbox("Protocol Type", ["tcp", "udp", "icmp"])
#     service = st.selectbox("Service", ["http", "smtp", "ftp", "other"])
#     flag = st.selectbox("Flag", ["SF", "S1", "REJ", "other"])
#     src_bytes = st.number_input("Source Bytes", min_value=0, max_value=100000, value=0)

#     if st.button('Predict'):
#         test = [duration, protocol, service, flag, src_bytes]
#         test_df = pd.DataFrame([test], columns=input_features)

#         # Ensure columns are in the correct order
#         full_test_df = pd.DataFrame(columns=full_feature_set)
#         full_test_df.loc[0, input_features] = test_df.loc[0, input_features]

#         # Impute the numerical values
#         numerical_cols = full_test_df.columns.difference(categorical_features)
#         full_test_df[numerical_cols] = num_imputer.transform(full_test_df[numerical_cols])

#         # Ensure columns are in the correct order after imputation
#         full_test_df = full_test_df[full_feature_set]

#         predicted_category = predict_category(full_test_df, model_choice)
#         st.write(f"Predicted Category: {predicted_category}")

# input()

# st.markdown('</div>', unsafe_allow_html=True)

##1
# import streamlit as st
# import pandas as pd
# import joblib
# from sklearn.impute import SimpleImputer
# from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
# from sklearn.preprocessing import StandardScaler, OneHotEncoder, LabelEncoder
# from sklearn.compose import ColumnTransformer
# from sklearn.pipeline import Pipeline
# from sklearn.svm import SVC
# from sklearn.model_selection import train_test_split
# # Load the trained models and other necessary objects
# svm_clf = joblib.load('svm_clf.pkl')
# label_encoder = joblib.load('label_encoder.pkl')
# num_imputer = joblib.load('num_imputer.pkl')

# # Column names for the NSL-KDD dataset
# col_names = ["duration", "protocol_type", "service", "flag", "src_bytes",
#              "dst_bytes", "land", "wrong_fragment", "urgent", "hot", "num_failed_logins",
#              "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root",
#              "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
#              "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
#              "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
#              "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
#              "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
#              "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
#              "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label"]

# # Load the dataset with specified column names
# file_path = 'NSL_KDD.csv'
# data = pd.read_csv(file_path, names=col_names, low_memory=False)

# # Define the mapping from detailed attack types to main categories
# category_mapping = {
#     'normal': 'normal',
#     'back': 'DoS',
#     'land': 'DoS',
#     'neptune': 'DoS',
#     'pod': 'DoS',
#     'smurf': 'DoS',
#     'teardrop': 'DoS',
#     'mailbomb': 'DoS',
#     'apache2': 'DoS',
#     'processtable': 'DoS',
#     'udpstorm': 'DoS',
#     'ftp_write': 'R2L',
#     'guess_passwd': 'R2L',
#     'imap': 'R2L',
#     'multihop': 'R2L',
#     'phf': 'R2L',
#     'spy': 'R2L',
#     'warezclient': 'R2L',
#     'warezmaster': 'R2L',
#     'sendmail': 'R2L',
#     'named': 'R2L',
#     'snmpgetattack': 'R2L',
#     'snmpguess': 'R2L',
#     'xlock': 'R2L',
#     'xsnoop': 'R2L',
#     'worm': 'R2L',
#     'buffer_overflow': 'U2R',
#     'loadmodule': 'U2R',
#     'perl': 'U2R',
#     'rootkit': 'U2R',
#     'httptunnel': 'U2R',
#     'ps': 'U2R',
#     'sqlattack': 'U2R',
#     'xterm': 'U2R',
#     'ipsweep': 'Probe',
#     'nmap': 'Probe',
#     'portsweep': 'Probe',
#     'satan': 'Probe',
#     'mscan': 'Probe',
#     'saint': 'Probe'
# }

# # Apply the mapping to the dataset
# data['label'] = data['label'].map(category_mapping)

# # Drop rows with unmapped labels (if any)
# data = data.dropna(subset=['label'])

# # Convert appropriate columns to numeric, using coercion to handle errors
# for col in col_names[:-1]:
#     data[col] = pd.to_numeric(data[col], errors='coerce')

# # Data preprocessing
# X = data.iloc[:, :-1]
# y = data.iloc[:, -1]

# # Identify categorical columns
# categorical_features = ["protocol_type", "service", "flag"]

# # Preprocessing for numerical and categorical features
# preprocessor = ColumnTransformer(
#     transformers=[
#         ('num', StandardScaler(), [col for col in X.columns if col not in categorical_features]),
#         ('cat', OneHotEncoder(handle_unknown='ignore'), categorical_features)
#     ]
# )
# def predict_category(test_df):
#     y_new = svm_clf.predict(test_df)
#     return label_encoder.inverse_transform(y_new)[0]

# def evaluate_model_metrics(y_true, y_pred):
#     accuracy = accuracy_score(y_true, y_pred)
#     precision = precision_score(y_true, y_pred, average='weighted')
#     recall = recall_score(y_true, y_pred, average='weighted')
#     f1 = f1_score(y_true, y_pred, average='weighted')

#     st.write("Support Vector Machine Metrics")
#     st.write(f"Accuracy: {accuracy:.4f}")
#     st.write(f"Precision: {precision:.4f}")
#     st.write(f"Recall: {recall:.4f}")
#     st.write(f"F1-score: {f1:.4f}")
# def show_predict_page():
#     st.title("Intrusion Detection System Prediction")

#     duration = st.number_input("Duration", min_value=0, max_value=100000, value=0)
#     protocol = st.selectbox("Protocol Type", ["tcp", "udp", "icmp"])
#     service = st.selectbox("Service", ["http", "smtp", "ftp", "other"])
#     flag = st.selectbox("Flag", ["SF", "S1", "REJ", "other"])
#     src_bytes = st.number_input("Source Bytes", min_value=0, max_value=100000, value=0)

#     if st.button('Predict'):
#         test = [[duration, protocol, service, flag, src_bytes]]
#         test_df = pd.DataFrame(test, columns=["duration", "protocol_type", "service", "flag", "src_bytes"])

#         # Preprocess input data
#         test_processed = preprocessor.transform(test_df)

#         # Predict using the SVM model
#         predicted_category = predict_category(test_processed)

#         # Display predicted category
#         st.write(f"Predicted Category: {predicted_category}")

#         # Display evaluation metrics for SVM model
#         evaluate_model_metrics(y, svm_clf.predict(X))

# show_predict_page()
##2
# import streamlit as st
# import pandas as pd
# import joblib
# from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
# from sklearn.impute import SimpleImputer
# from sklearn.preprocessing import LabelEncoder
# from sklearn.model_selection import train_test_split

# # Load the trained models and other necessary objects
# rf_clf = joblib.load('rf_clf.pkl')
# svm_clf = joblib.load('svm_clf.pkl')
# voting_clf = joblib.load('voting_clf.pkl')
# label_encoder = joblib.load('label_encoder.pkl')
# num_imputer = joblib.load('num_imputer.pkl')

# # Column names for the NSL-KDD dataset
# full_feature_set = ["duration", "protocol_type", "service", "flag", "src_bytes",
#                     "dst_bytes", "land", "wrong_fragment", "urgent", "hot", "num_failed_logins",
#                     "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root",
#                     "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
#                     "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
#                     "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
#                     "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
#                     "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
#                     "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
#                     "dst_host_rerror_rate", "dst_host_srv_rerror_rate"]

# input_features = ["duration", "protocol_type", "service", "flag", "src_bytes"]

# # ColumnTransformer preprocessing object
# categorical_features = ["protocol_type", "service", "flag"]

# # Function to predict category based on the selected model
# def predict_category(test_df, model_choice):
#     if model_choice == "Random Forest":
#         y_new = rf_clf.predict(test_df)
#     elif model_choice == "Support Vector Machine":
#         y_new = svm_clf.predict(test_df)
#     elif model_choice == "Ensembling":
#         y_new = voting_clf.predict(test_df)
    
#     predicted_category = label_encoder.inverse_transform(y_new)[0]
    
#     # Determine if it's normal or attack based on your label mapping
#     if predicted_category == 'normal':
#         return "Normal"
#     else:
#         return "Attack"

# # Function to evaluate model metrics and display confusion matrix
# def evaluate_model_metrics(y_true, y_pred, model_name):
#     accuracy = accuracy_score(y_true, y_pred)
#     precision = precision_score(y_true, y_pred, average='weighted')
#     recall = recall_score(y_true, y_pred, average='weighted')
#     f1 = f1_score(y_true, y_pred, average='weighted')
#     cm = confusion_matrix(y_true, y_pred)

#     st.write(f"### {model_name} Metrics")
#     st.write(f"Accuracy: {accuracy:.4f}")
#     st.write(f"Precision: {precision:.4f}")
#     st.write(f"Recall: {recall:.4f}")
#     st.write(f"F1-score: {f1:.4f}")

#     st.write(f"### {model_name} Confusion Matrix")
#     st.write(cm)

# # Streamlit UI for the prediction page
# def show_predict_page():
#     st.markdown(
#         """
#         <style>
#         .full-app-container {
#             background: linear-gradient(to right, #64469a, #3b0234); 
#             width: 100%;
#             height: 100%;
#             position: fixed;
#             top: 0;
#             left: 0;
#             overflow: auto;
#         }
#         header {
#             background: linear-gradient(to right, #64469a, #3b0234) !important;
#         }
#         .css-1a32fsj.edgvbvh10 {
#             background-color: #044455 !important;
#             color: white !important;
#         }
#         .predict_button {
#             width: 200px;
#             height: 60px;
#             font-size: 20px;
#         }
#         </style>
#         """,
#         unsafe_allow_html=True
#     )
#     st.markdown('<div class="full-app-container">', unsafe_allow_html=True)

# show_predict_page()

# # Streamlit UI for user input and prediction
# def input():
#     st.title("Intrusion Detection System Prediction")

#     model_choice = st.selectbox("Choose a machine learning model", ["Random Forest", "Support Vector Machine", "Ensembling"])

#     duration = st.number_input("Duration", min_value=0, max_value=100000, value=0)
#     protocol = st.selectbox("Protocol Type", ["tcp", "udp", "icmp"])
#     service = st.selectbox("Service", ["http", "smtp", "ftp", "other"])
#     flag = st.selectbox("Flag", ["SF", "S1", "REJ", "other"])
#     src_bytes = st.number_input("Source Bytes", min_value=0, max_value=100000, value=0)

#     if st.button('Predict'):
#         test = [duration, protocol, service, flag, src_bytes]
#         test_df = pd.DataFrame([test], columns=input_features)

#         # Ensure columns are in the correct order
#         full_test_df = pd.DataFrame(columns=full_feature_set)
#         full_test_df.loc[0, input_features] = test_df.loc[0, input_features]

#         # Impute the numerical values
#         numerical_cols = full_test_df.columns.difference(categorical_features)
#         full_test_df[numerical_cols] = num_imputer.transform(full_test_df[numerical_cols])

#         # Ensure columns are in the correct order after imputation
#         full_test_df = full_test_df[full_feature_set]

#         # Generate predictions
#         if model_choice == "Random Forest":
#             y_pred = rf_clf.predict(full_test_df)
#         elif model_choice == "Support Vector Machine":
#             y_pred = svm_clf.predict(full_test_df)
#         elif model_choice == "Ensembling":
#             y_pred = voting_clf.predict(full_test_df)

#         # Simulate y_test for demonstration (replace this with actual y_test from your dataset)
#         # Example: y_test = loaded_test_data['actual_labels']

#         # Simulate the true labels for demonstration purposes
#         y_test = [0]  # Replace with your actual y_test data

#         # Evaluate model metrics and display confusion matrix
#         evaluate_model_metrics(y_test, y_pred, model_choice)

#         # Display predicted category
#         predicted_category = predict_category(full_test_df, model_choice)
#         st.write(f"Predicted Category: {predicted_category}")

# input()

# st.markdown('</div>', unsafe_allow_html=True)

##3
# import streamlit as st
# import pandas as pd
# import joblib
# import matplotlib.pyplot as plt
# from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
# from sklearn.impute import SimpleImputer
# from sklearn.preprocessing import LabelEncoder
# from sklearn.model_selection import train_test_split
# from PIL import Image  # Required for loading image
# # Load the trained models and other necessary objects
# rf_clf = joblib.load('rf_clf.pkl')
# svm_clf = joblib.load('svm_clf.pkl')
# voting_clf = joblib.load('voting_clf.pkl')
# label_encoder = joblib.load('label_encoder.pkl')
# num_imputer = joblib.load('num_imputer.pkl')

# # Column names for the NSL-KDD dataset
# full_feature_set = ["duration", "protocol_type", "service", "flag", "src_bytes",
#                     "dst_bytes", "land", "wrong_fragment", "urgent", "hot", "num_failed_logins",
#                     "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root",
#                     "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
#                     "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
#                     "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
#                     "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
#                     "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
#                     "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
#                     "dst_host_rerror_rate", "dst_host_srv_rerror_rate"]

# input_features = ["duration", "protocol_type", "service", "flag", "src_bytes"]

# # ColumnTransformer preprocessing object
# categorical_features = ["protocol_type", "service", "flag"]
# # Function to predict category based on the selected model
# def predict_category(test_df, model_choice):
#     if model_choice == "Random Forest":
#         y_new = rf_clf.predict(test_df)
#     elif model_choice == "Support Vector Machine":
#         y_new = svm_clf.predict(test_df)
#     elif model_choice == "Ensembling":
#         y_new = voting_clf.predict(test_df)
    
#     predicted_category = label_encoder.inverse_transform(y_new)[0]
    
#     # Determine if it's normal or attack based on your label mapping
#     if predicted_category == 'normal':
#         return "Normal"
#     else:
#         return "Attack"

# # Function to evaluate model metrics and display confusion matrix
# def evaluate_model_metrics(y_true, y_pred, model_name):
#     accuracy = accuracy_score(y_true, y_pred)
#     precision = precision_score(y_true, y_pred, average='weighted')
#     recall = recall_score(y_true, y_pred, average='weighted')
#     f1 = f1_score(y_true, y_pred, average='weighted')
#     cm = confusion_matrix(y_true, y_pred)

#     st.write(f"### {model_name} Metrics")
#     st.write(f"Accuracy: {accuracy:.4f}")
#     st.write(f"Precision: {precision:.4f}")
#     st.write(f"Recall: {recall:.4f}")
#     st.write(f"F1-score: {f1:.4f}")

#     st.write(f"### {model_name} Confusion Matrix")
#     st.write(cm)

#     # Save confusion matrix plot as an image file
#     plt.figure(figsize=(8, 6))
#     plt.imshow(cm, interpolation='nearest', cmap=plt.cm.Blues)
#     plt.title(f"{model_name} Confusion Matrix")
#     plt.colorbar()
#     tick_marks = range(len(label_encoder.classes_))
#     plt.xticks(tick_marks, label_encoder.classes_, rotation=45)
#     plt.yticks(tick_marks, label_encoder.classes_)
#     plt.xlabel('Predicted Label')
#     plt.ylabel('True Label')
#     plt.tight_layout()

#     # Save plot to a temporary image file
#     if model_name=="Support Vector Machine":
#         temp_image = "support_vector_machine_confusion_matrix.png"
#     elif model_name=="Random Forest":
#         temp_image = "random_forest_confusion_matrix.png"
#     else:
#         temp_image = "ensembling_confusion_matrix.png"
#     plt.savefig(temp_image)

#     # Display the image using PIL
#     image = Image.open(temp_image)
#     st.image(image, caption=f"{model_name} Confusion Matrix", use_column_width=True)
# def show_predict_page():
#     st.markdown(
#         """
#         <style>
#         .full-app-container {
#             background: linear-gradient(to right, #64469a, #3b0234); 
#             width: 100%;
#             height: 100%;
#             position: fixed;
#             top: 0;
#             left: 0;
#             overflow: auto;
#         }
#         header {
#             background: linear-gradient(to right, #64469a, #3b0234) !important;
#         }
#         .css-1a32fsj.edgvbvh10 {
#             background-color: #044455 !important;
#             color: white !important;
#         }
#         .predict_button {
#             width: 200px;
#             height: 60px;
#             font-size: 20px;
#         }
#         </style>
#         """,
#         unsafe_allow_html=True
#     )
#     st.markdown('<div class="full-app-container">', unsafe_allow_html=True)

# show_predict_page()

# # Streamlit UI for user input and prediction
# def input():
#     st.title("Intrusion Detection System Prediction")

#     model_choice = st.selectbox("Choose a machine learning model", ["Random Forest", "Support Vector Machine", "Ensembling"])

#     duration = st.number_input("Duration", min_value=0, max_value=100000, value=0)
#     protocol = st.selectbox("Protocol Type", ["tcp", "udp", "icmp"])
#     service = st.selectbox("Service", ["http", "smtp", "ftp", "other"])
#     flag = st.selectbox("Flag", ["SF", "S1", "REJ", "other"])
#     src_bytes = st.number_input("Source Bytes", min_value=0, max_value=100000, value=0)

#     if st.button('Predict'):
#         test = [duration, protocol, service, flag, src_bytes]
#         test_df = pd.DataFrame([test], columns=input_features)

#         # Ensure columns are in the correct order
#         full_test_df = pd.DataFrame(columns=full_feature_set)
#         full_test_df.loc[0, input_features] = test_df.loc[0, input_features]

#         # Impute the numerical values
#         numerical_cols = full_test_df.columns.difference(categorical_features)
#         full_test_df[numerical_cols] = num_imputer.transform(full_test_df[numerical_cols])

#         # Ensure columns are in the correct order after imputation
#         full_test_df = full_test_df[full_feature_set]

#         # Generate predictions
#         if model_choice == "Random Forest":
#             y_pred = rf_clf.predict(full_test_df)
#         elif model_choice == "Support Vector Machine":
#             y_pred = svm_clf.predict(full_test_df)
#         elif model_choice == "Ensembling":
#             y_pred = voting_clf.predict(full_test_df)

#         # Simulate y_test for demonstration (replace this with actual y_test from your dataset)
#         # Example: y_test = loaded_test_data['actual_labels']

#         # Simulate the true labels for demonstration purposes
#         y_test = [0]  # Replace with your actual y_test data

#         # Evaluate model metrics and display confusion matrix
#         evaluate_model_metrics(y_test, y_pred, model_choice)

#         # Display predicted category
#         predicted_category = predict_category(full_test_df, model_choice)
#         st.write(f"Predicted Category: {predicted_category}")

# input()

# st.markdown('</div>', unsafe_allow_html=True)

##4
# import streamlit as st
# import pandas as pd
# import joblib
# import matplotlib.pyplot as plt
# from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
# from sklearn.impute import SimpleImputer
# from sklearn.preprocessing import LabelEncoder
# from PIL import Image  # Required for loading image

# # Load the trained models and other necessary objects
# rf_clf = joblib.load('rf_clf.pkl')
# svm_clf = joblib.load('svm_clf.pkl')
# voting_clf = joblib.load('voting_clf.pkl')
# label_encoder = joblib.load('label_encoder.pkl')
# num_imputer = joblib.load('num_imputer.pkl')
# # attack_mapping = joblib.load('attack_mapping.pkl')

# # Load the classification reports
# rf_report = joblib.load('rf_report.pkl')
# svm_report = joblib.load('svm_report.pkl')
# voting_report = joblib.load('voting_report.pkl')

# # Column names for the NSL-KDD dataset
# full_feature_set = ["duration", "protocol_type", "service", "flag", "src_bytes",
#                     "dst_bytes", "land", "wrong_fragment", "urgent", "hot", "num_failed_logins",
#                     "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root",
#                     "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
#                     "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
#                     "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
#                     "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
#                     "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
#                     "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
#                     "dst_host_rerror_rate", "dst_host_srv_rerror_rate"]

# input_features = ["duration", "protocol_type", "service", "flag", "src_bytes"]

# # ColumnTransformer preprocessing object
# categorical_features = ["protocol_type", "service", "flag"]

# # Function to predict category based on the selected model
# def predict_category(test_df, model_choice):
#     if model_choice == "Random Forest":
#         y_new = rf_clf.predict(test_df)
#     elif model_choice == "Support Vector Machine":
#         y_new = svm_clf.predict(test_df)
#     elif model_choice == "Ensembling":
#         y_new = voting_clf.predict(test_df)
    
#     predicted_category = label_encoder.inverse_transform(y_new)[0]
    
#     # Determine if it's normal or attack based on your label mapping
#     if predicted_category == 'normal':
#         return "Normal"
#     else:
#         return "Attack"

# # Function to evaluate model metrics and display confusion matrix
# def evaluate_model_metrics(y_true, y_pred, model_name):
#     # accuracy = accuracy_score(y_true, y_pred)
#     # precision = precision_score(y_true, y_pred, average='weighted')
#     # recall = recall_score(y_true, y_pred, average='weighted')
#     # f1 = f1_score(y_true, y_pred, average='weighted')
#     # cm = confusion_matrix(y_true, y_pred)

#     # st.write(f"### {model_name} Metrics")
#     # st.write(f"Accuracy: {accuracy:.4f}")
#     # st.write(f"Precision: {precision:.4f}")
#     # st.write(f"Recall: {recall:.4f}")
#     # st.write(f"F1-score: {f1:.4f}")

#     # st.write(f"### {model_name} Confusion Matrix")
#     # st.write(cm)

#     # Save confusion matrix plot as an image file
#     # plt.figure(figsize=(8, 6))
#     # plt.imshow(cm, interpolation='nearest', cmap=plt.cm.Blues)
#     # plt.title(f"{model_name} Confusion Matrix")
#     # plt.colorbar()
#     # tick_marks = range(len(label_encoder.classes_))
#     # plt.xticks(tick_marks, label_encoder.classes_, rotation=45)
#     # plt.yticks(tick_marks, label_encoder.classes_)
#     # plt.xlabel('Predicted Label')
#     # plt.ylabel('True Label')
#     # plt.tight_layout()

#     # Save plot to a temporary image file
#     if model_name == "Random Forest":
#         temp_image = "random_forest_confusion_matrix.png"
#     elif model_name == "Support Vector Machine":
#         temp_image = "support_vector_machine_confusion_matrix.png"
#     elif model_name == "Ensembling":
#         temp_image = "ensembling_confusion_matrix.png"
#     # temp_image = f"{model_name.lower().replace(' ', '_')}_confusion_matrix.png"
#     # plt.savefig(temp_image)

# #     # Display the image using PIL
#     image = Image.open(temp_image)
#     st.image(image, caption=f"{model_name} Confusion Matrix", use_column_width=True)    
#     # Save confusion matrix plot as an image file
#     # if model_name == "Random Forest":
#     #     temp_image = "random_forest_confusion_matrix.png"
#     # elif model_name == "Support Vector Machine":
#     #     temp_image = "support_vector_machine_confusion_matrix.png"
#     # elif model_name == "Ensembling":
#     #     temp_image = "ensembling_confusion_matrix.png"
    
#     # plt.figure(figsize=(8, 6))
#     # plt.imshow(cm, interpolation='nearest', cmap=plt.cm.Blues)
#     # plt.title(f"{model_name} Confusion Matrix")
#     # plt.colorbar()
#     # tick_marks = range(len(label_encoder.classes_))
#     # plt.xticks(tick_marks, label_encoder.classes_, rotation=45)
#     # plt.yticks(tick_marks, label_encoder.classes_)
#     # plt.xlabel('Predicted Label')
#     # plt.ylabel('True Label')
#     # plt.tight_layout()
#     # plt.savefig(temp_image)

#     # # Display the image using PIL
#     # image = Image.open(temp_image)
#     # st.image(image, caption=f"{model_name} Confusion Matrix", use_column_width=True)

# def show_predict_page():
#     st.markdown(
#         """
#         <style>
#         .full-app-container {
#             background: linear-gradient(to right, #780206, #061161); 
#             width: 100%;
#             height: 100%;
#             position: fixed;
#             top: 0;
#             left: 0;
#             overflow: auto;
#         }
#         header {
#             background: linear-gradient(to right, #780206, #061161) !important;
#         }
#         .css-1a32fsj.edgvbvh10 {
#             background-color: #044455 !important;
#             color: white !important;
#         }
#         .predict_button {
#             width: 200px;
#             height: 60px;
#             font-size: 20px;
#         }
#         </style>
#         """,
#         unsafe_allow_html=True
#     )
#     st.markdown('<div class="full-app-container">', unsafe_allow_html=True)

# show_predict_page()

# # Streamlit UI for user input and prediction
# def input():
#     st.title("Intrusion Detection System Prediction")

#     model_choice = st.selectbox("Choose a machine learning model", ["Random Forest", "Support Vector Machine", "Ensembling"])

#     duration = st.number_input("Duration", min_value=0, max_value=100000, value=0)
#     protocol = st.selectbox("Protocol Type", ["tcp", "udp", "icmp"])
#     service = st.selectbox("Service", ["http", "smtp", "ftp", "other"])
#     flag = st.selectbox("Flag", ["SF", "S1", "REJ", "other"])
#     src_bytes = st.number_input("Source Bytes", min_value=0, max_value=100000, value=0)

#     if st.button('Predict'):
#         test = [duration, protocol, service, flag, src_bytes]
#         test_df = pd.DataFrame([test], columns=input_features)

#         # Ensure columns are in the correct order
#         full_test_df = pd.DataFrame(columns=full_feature_set)
#         full_test_df.loc[0, input_features] = test_df.loc[0, input_features]

#         # Impute the numerical values
#         numerical_cols = full_test_df.columns.difference(categorical_features)
#         full_test_df[numerical_cols] = num_imputer.transform(full_test_df[numerical_cols])

#         # Ensure columns are in the correct order after imputation
#         full_test_df = full_test_df[full_feature_set]

#         # Generate predictions
#         if model_choice == "Random Forest":
#             y_pred = rf_clf.predict(full_test_df)
#         elif model_choice == "Support Vector Machine":
#             y_pred = svm_clf.predict(full_test_df)
#         elif model_choice == "Ensembling":
#             y_pred = voting_clf.predict(full_test_df)

#         # Simulate y_test for demonstration (replace this with actual y_test from your dataset)
#         y_test = [0]  # Replace with your actual y_test data

#         # Evaluate model metrics and display confusion matrix
#         # evaluate_model_metrics(y_test, y_pred, model_choice)

#         # Display predicted category
#         predicted_category = predict_category(full_test_df, model_choice)
#         st.write(f"Predicted Category: {predicted_category}")
#         # Evaluate model metrics and display confusion matrix
#         evaluate_model_metrics(y_test, y_pred, model_choice)

#         # Display the classification report
#         if model_choice == "Random Forest":
#             st.write("### Random Forest Classification Report")
#             st.json(rf_report)
#         elif model_choice == "Support Vector Machine":
#             st.write("### Support Vector Machine Classification Report")
#             st.json(svm_report)
#         elif model_choice == "Ensembling":
#             st.write("### Ensembling Classification Report")
#             st.json(voting_report)

# input()

# st.markdown('</div>', unsafe_allow_html=True)

##5
# import streamlit as st
# import pandas as pd
# import joblib
# import matplotlib.pyplot as plt
# from sklearn.impute import SimpleImputer
# from sklearn.preprocessing import LabelEncoder
# from PIL import Image

# # Load the trained models and other necessary objects
# rf_clf = joblib.load('rf_clf.pkl')
# svm_clf = joblib.load('svm_clf.pkl')
# voting_clf = joblib.load('voting_clf.pkl')
# label_encoder = joblib.load('label_encoder.pkl')
# num_imputer = joblib.load('num_imputer.pkl')
# attack_mapping = joblib.load('attack_mapping.pkl')

# # Load the classification reports
# rf_report = joblib.load('rf_report.pkl')
# svm_report = joblib.load('svm_report.pkl')
# voting_report = joblib.load('voting_report.pkl')

# # Column names for the NSL-KDD dataset
# full_feature_set = ["duration", "protocol_type", "service", "flag", "src_bytes",
#                     "dst_bytes", "land", "wrong_fragment", "urgent", "hot", "num_failed_logins",
#                     "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root",
#                     "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
#                     "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
#                     "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
#                     "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
#                     "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
#                     "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
#                     "dst_host_rerror_rate", "dst_host_srv_rerror_rate"]

# input_features = ["duration", "protocol_type", "service", "flag", "src_bytes"]

# # ColumnTransformer preprocessing object
# categorical_features = ["protocol_type", "service", "flag"]

# # Function to predict category and type of attack based on the selected model
# def predict_category_and_attack(test_df, model_choice):
#     if model_choice == "Random Forest":
#         y_new = rf_clf.predict(test_df)
#     elif model_choice == "Support Vector Machine":
#         y_new = svm_clf.predict(test_df)
#     elif model_choice == "Ensembling":
#         y_new = voting_clf.predict(test_df)
    
#     predicted_category = label_encoder.inverse_transform(y_new)[0]
    
#     if predicted_category == 'normal':
#         return "Normal", None
#     else:
#         attack_type = attack_mapping.get(predicted_category, "Unknown")
#         return "Attack", attack_type

# # Function to evaluate model metrics and display confusion matrix
# def evaluate_model_metrics(y_true, y_pred, model_name):
#     # Save plot to a temporary image file
#     if model_name == "Random Forest":
#         temp_image = "random_forest_confusion_matrix.png"
#     elif model_name == "Support Vector Machine":
#         temp_image = "support_vector_machine_confusion_matrix.png"
#     elif model_name == "Ensembling":
#         temp_image = "ensembling_confusion_matrix.png"

#     # Display the image using PIL
#     image = Image.open(temp_image)
#     st.image(image, caption=f"{model_name} Confusion Matrix", use_column_width=True)    

# def show_predict_page():
#     st.markdown(
#         """
#         <style>
#         .full-app-container {
#             background: linear-gradient(to right, #780206, #061161); 
#             width: 100%;
#             height: 100%;
#             position: fixed;
#             top: 0;
#             left: 0;
#             overflow: auto;
#         }
#         header {
#             background: linear-gradient(to right, #780206, #061161) !important;
#         }
#         .css-1a32fsj.edgvbvh10 {
#             background-color: #044455 !important;
#             color: white !important;
#         }
#         .predict_button {
#             width: 200px;
#             height: 60px;
#             font-size: 20px;
#         }
#         </style>
#         """,
#         unsafe_allow_html=True
#     )
#     st.markdown('<div class="full-app-container">', unsafe_allow_html=True)

# show_predict_page()

# # Streamlit UI for user input and prediction
# def input():
#     st.title("Intrusion Detection System Prediction")

#     model_choice = st.selectbox("Choose a machine learning model", ["Random Forest", "Support Vector Machine", "Ensembling"])

#     duration = st.number_input("Duration", min_value=0, max_value=100000, value=0)
#     protocol = st.selectbox("Protocol Type", ["tcp", "udp", "icmp"])
#     service = st.selectbox("Service", ["http", "smtp", "ftp", "other"])
#     flag = st.selectbox("Flag", ["SF", "S1", "REJ", "other"])
#     src_bytes = st.number_input("Source Bytes", min_value=0, max_value=100000, value=0)

#     if st.button('Predict'):
#         test = [duration, protocol, service, flag, src_bytes]
#         test_df = pd.DataFrame([test], columns=input_features)

#         # Ensure columns are in the correct order
#         full_test_df = pd.DataFrame(columns=full_feature_set)
#         full_test_df.loc[0, input_features] = test_df.loc[0, input_features]

#         # Impute the numerical values
#         numerical_cols = full_test_df.columns.difference(categorical_features)
#         full_test_df[numerical_cols] = num_imputer.transform(full_test_df[numerical_cols])

#         # Ensure columns are in the correct order after imputation
#         full_test_df = full_test_df[full_feature_set]

#         # Generate predictions
#         if model_choice == "Random Forest":
#             y_pred = rf_clf.predict(full_test_df)
#             st.write(f"Predicted Category: {label_encoder.inverse_transform(y_pred)[0]}")
#         elif model_choice == "Support Vector Machine":
#             y_pred = svm_clf.predict(full_test_df)
#             st.write(f"Predicted Category: {label_encoder.inverse_transform(y_pred)[0]}")
#         elif model_choice == "Ensembling":
#             st.write(f"Predicted Category: {label_encoder.inverse_transform(y_pred)[0]}")

#         # Simulate y_test for demonstration (replace this with actual y_test from your dataset)
#         y_test = [0]  # Replace with your actual y_test data

#         # Evaluate model metrics and display confusion matrix
#         # evaluate_model_metrics(y_test, y_pred, model_choice)

#         # Display predicted category and attack type
#         predicted_category, attack_type = predict_category_and_attack(full_test_df, model_choice)
#         st.write(f"Predicted Category: {predicted_category}")
#         if attack_type:
#             st.write(f"Type of Attack: {attack_type}")

#         # Evaluate model metrics and display confusion matrix
#         evaluate_model_metrics(y_test, y_pred, model_choice)

#         # Display the classification report
#         if model_choice == "Random Forest":
#             st.write("### Random Forest Classification Report")
#             st.json(rf_report)
#         elif model_choice == "Support Vector Machine":
#             st.write("### Support Vector Machine Classification Report")
#             st.json(svm_report)
#         elif model_choice == "Ensembling":
#             st.write("### Ensembling Classification Report")
#             st.json(voting_report)

# input()

# st.markdown('</div>', unsafe_allow_html=True)

##6
import streamlit as st
import pandas as pd
import joblib
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
def evaluate_model_metrics(y_true, y_pred, model_name):
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

        # Create a full DataFrame with all columns and fill with NaN or default values
        full_test_df = pd.DataFrame(columns=full_feature_set)
        full_test_df = pd.concat([full_test_df, pd.DataFrame([test], columns=input_features)], ignore_index=True)

        # Impute the numerical values
        numerical_cols = full_test_df.columns.difference(categorical_features)
        full_test_df[numerical_cols] = num_imputer.transform(full_test_df[numerical_cols])

        # Generate predictions
        y_pred = None
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

        # Skip the evaluation if y_test is not available
        # Uncomment and provide actual y_test if you have it
        # y_test = [your_actual_y_test]
        # evaluate_model_metrics(y_test, y_pred, model_choice)

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

input()

st.markdown('</div>', unsafe_allow_html=True)

