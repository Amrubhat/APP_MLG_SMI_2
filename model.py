# import pandas as pd
# from sklearn.model_selection import train_test_split
# from sklearn.preprocessing import StandardScaler, OneHotEncoder, LabelEncoder
# from sklearn.compose import ColumnTransformer
# from sklearn.pipeline import Pipeline
# from sklearn.ensemble import RandomForestClassifier, VotingClassifier
# from sklearn.svm import SVC
# from sklearn.impute import SimpleImputer
# import joblib

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

# # Impute missing values for numerical data
# num_imputer = SimpleImputer(strategy='mean')
# X.loc[:, X.columns.difference(['protocol_type', 'service', 'flag'])] = num_imputer.fit_transform(X.loc[:, X.columns.difference(['protocol_type', 'service', 'flag'])])

# # Encode the target variable if it's categorical
# label_encoder = LabelEncoder()
# y = label_encoder.fit_transform(y)

# # Identify categorical columns
# categorical_features = ["protocol_type", "service", "flag"]

# # Preprocessing for numerical and categorical features
# preprocessor = ColumnTransformer(
#     transformers=[
#         ('num', StandardScaler(), [col for col in X.columns if col not in categorical_features]),
#         ('cat', OneHotEncoder(handle_unknown='ignore'), categorical_features)
#     ]
# )

# # Split the dataset into training and testing sets
# X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# # Creating a pipeline that includes preprocessing and the object for the random forest classifier
# rf_clf = Pipeline(steps=[('preprocessor', preprocessor), ('classifier', RandomForestClassifier(n_estimators=100, random_state=42))])

# # Creating a pipeline that includes preprocessing and the object for the support vector machine classifier
# svm_clf = Pipeline(steps=[('preprocessor', preprocessor), ('classifier', SVC(kernel='linear', random_state=42))])

# # Creating a pipeline that includes preprocessing and the object for the ensembling voter classifier
# voting_clf = Pipeline(steps=[('preprocessor', preprocessor), ('classifier', VotingClassifier(estimators=[('rf', RandomForestClassifier(n_estimators=100, random_state=42)), ('svc', SVC(kernel='linear', random_state=42))], voting='hard'))])

# # Fitting the models
# rf_clf.fit(X_train, y_train)
# svm_clf.fit(X_train, y_train)
# voting_clf.fit(X_train, y_train)

# # Save the trained models to pickle files
# joblib.dump(rf_clf, 'rf_clf.pkl')
# joblib.dump(svm_clf, 'svm_clf.pkl')
# joblib.dump(voting_clf, 'voting_clf.pkl')
# joblib.dump(label_encoder, 'label_encoder.pkl')
# joblib.dump(num_imputer, 'num_imputer.pkl')

##1
# import pandas as pd
# from sklearn.model_selection import train_test_split
# from sklearn.preprocessing import StandardScaler, OneHotEncoder, LabelEncoder
# from sklearn.compose import ColumnTransformer
# from sklearn.pipeline import Pipeline
# from sklearn.ensemble import RandomForestClassifier, VotingClassifier
# from sklearn.svm import SVC
# from sklearn.impute import SimpleImputer
# from sklearn.metrics import classification_report, accuracy_score
# import joblib

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

# # Impute missing values for numerical data
# num_imputer = SimpleImputer(strategy='mean')
# X.loc[:, X.columns.difference(['protocol_type', 'service', 'flag'])] = num_imputer.fit_transform(X.loc[:, X.columns.difference(['protocol_type', 'service', 'flag'])])

# # Encode the target variable if it's categorical
# label_encoder = LabelEncoder()
# y = label_encoder.fit_transform(y)

# # Identify categorical columns
# categorical_features = ["protocol_type", "service", "flag"]

# # Preprocessing for numerical and categorical features
# preprocessor = ColumnTransformer(
#     transformers=[
#         ('num', StandardScaler(), [col for col in X.columns if col not in categorical_features]),
#         ('cat', OneHotEncoder(handle_unknown='ignore'), categorical_features)
#     ]
# )

# # Split the dataset into training and testing sets
# X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# # Creating a pipeline that includes preprocessing and the object for the random forest classifier
# rf_clf = Pipeline(steps=[('preprocessor', preprocessor), ('classifier', RandomForestClassifier(n_estimators=100, random_state=42))])

# # Creating a pipeline that includes preprocessing and the object for the support vector machine classifier
# svm_clf = Pipeline(steps=[('preprocessor', preprocessor), ('classifier', SVC(kernel='linear', random_state=42))])

# # Creating a pipeline that includes preprocessing and the object for the ensembling voter classifier
# voting_clf = Pipeline(steps=[('preprocessor', preprocessor), ('classifier', VotingClassifier(estimators=[('rf', RandomForestClassifier(n_estimators=100, random_state=42)), ('svc', SVC(kernel='linear', random_state=42))], voting='hard'))])

# # Fitting the models
# rf_clf.fit(X_train, y_train)
# svm_clf.fit(X_train, y_train)
# voting_clf.fit(X_train, y_train)

# # Evaluate the models
# rf_predictions = rf_clf.predict(X_test)
# svm_predictions = svm_clf.predict(X_test)
# voting_predictions = voting_clf.predict(X_test)

# # Calculate accuracy, precision, recall, and F1-score
# rf_report = classification_report(y_test, rf_predictions, target_names=label_encoder.classes_, output_dict=True)
# svm_report = classification_report(y_test, svm_predictions, target_names=label_encoder.classes_, output_dict=True)
# voting_report = classification_report(y_test, voting_predictions, target_names=label_encoder.classes_, output_dict=True)

# # Save the trained models and the reports to pickle files
# joblib.dump(rf_clf, 'rf_clf.pkl')
# joblib.dump(svm_clf, 'svm_clf.pkl')
# joblib.dump(voting_clf, 'voting_clf.pkl')
# joblib.dump(label_encoder, 'label_encoder.pkl')
# joblib.dump(num_imputer, 'num_imputer.pkl')
# joblib.dump(rf_report, 'rf_report.pkl')
# joblib.dump(svm_report, 'svm_report.pkl')
# joblib.dump(voting_report, 'voting_report.pkl')

##2
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, OneHotEncoder, LabelEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.svm import SVC
from sklearn.impute import SimpleImputer
from sklearn.metrics import classification_report, accuracy_score
import joblib

# Column names for the NSL-KDD dataset
col_names = ["duration", "protocol_type", "service", "flag", "src_bytes",
             "dst_bytes", "land", "wrong_fragment", "urgent", "hot", "num_failed_logins",
             "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root",
             "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
             "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
             "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
             "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
             "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
             "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
             "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label"]

# Load the dataset with specified column names
file_path = 'NSL_KDD.csv'
data = pd.read_csv(file_path, names=col_names, low_memory=False)

# Define the mapping from detailed attack types to main categories
category_mapping = {
    'normal': 'normal',
    'back': 'DoS',
    'land': 'DoS',
    'neptune': 'DoS',
    'pod': 'DoS',
    'smurf': 'DoS',
    'teardrop': 'DoS',
    'mailbomb': 'DoS',
    'apache2': 'DoS',
    'processtable': 'DoS',
    'udpstorm': 'DoS',
    'ftp_write': 'R2L',
    'guess_passwd': 'R2L',
    'imap': 'R2L',
    'multihop': 'R2L',
    'phf': 'R2L',
    'spy': 'R2L',
    'warezclient': 'R2L',
    'warezmaster': 'R2L',
    'sendmail': 'R2L',
    'named': 'R2L',
    'snmpgetattack': 'R2L',
    'snmpguess': 'R2L',
    'xlock': 'R2L',
    'xsnoop': 'R2L',
    'worm': 'R2L',
    'buffer_overflow': 'U2R',
    'loadmodule': 'U2R',
    'perl': 'U2R',
    'rootkit': 'U2R',
    'httptunnel': 'U2R',
    'ps': 'U2R',
    'sqlattack': 'U2R',
    'xterm': 'U2R',
    'ipsweep': 'Probe',
    'nmap': 'Probe',
    'portsweep': 'Probe',
    'satan': 'Probe',
    'mscan': 'Probe',
    'saint': 'Probe'
}

# Apply the mapping to the dataset
data['label'] = data['label'].map(category_mapping)

# Save the attack type mappings
attack_mapping = {v: k for k, v in category_mapping.items()}
joblib.dump(attack_mapping, 'attack_mapping.pkl')

# Drop rows with unmapped labels (if any)
data = data.dropna(subset=['label'])

# Convert appropriate columns to numeric, using coercion to handle errors
for col in col_names[:-1]:
    data[col] = pd.to_numeric(data[col], errors='coerce')

# Data preprocessing
X = data.iloc[:, :-1]
y = data.iloc[:, -1]

# Impute missing values for numerical data
num_imputer = SimpleImputer(strategy='mean')
X.loc[:, X.columns.difference(['protocol_type', 'service', 'flag'])] = num_imputer.fit_transform(X.loc[:, X.columns.difference(['protocol_type', 'service', 'flag'])])

# Encode the target variable if it's categorical
label_encoder = LabelEncoder()
y = label_encoder.fit_transform(y)

# Identify categorical columns
categorical_features = ["protocol_type", "service", "flag"]

# Preprocessing for numerical and categorical features
preprocessor = ColumnTransformer(
    transformers=[
        ('num', StandardScaler(), [col for col in X.columns if col not in categorical_features]),
        ('cat', OneHotEncoder(handle_unknown='ignore'), categorical_features)
    ]
)

# Split the dataset into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Creating a pipeline that includes preprocessing and the object for the random forest classifier
rf_clf = Pipeline(steps=[('preprocessor', preprocessor), ('classifier', RandomForestClassifier(n_estimators=100, random_state=42))])

# Creating a pipeline that includes preprocessing and the object for the support vector machine classifier
svm_clf = Pipeline(steps=[('preprocessor', preprocessor), ('classifier', SVC(kernel='linear', random_state=42))])

# Creating a pipeline that includes preprocessing and the object for the ensembling voter classifier
voting_clf = Pipeline(steps=[('preprocessor', preprocessor), ('classifier', VotingClassifier(estimators=[('rf', RandomForestClassifier(n_estimators=100, random_state=42)), ('svc', SVC(kernel='linear', random_state=42))], voting='hard'))])

# Fitting the models
rf_clf.fit(X_train, y_train)
svm_clf.fit(X_train, y_train)
voting_clf.fit(X_train, y_train)

# Evaluate the models
rf_predictions = rf_clf.predict(X_test)
svm_predictions = svm_clf.predict(X_test)
voting_predictions = voting_clf.predict(X_test)

# Calculate accuracy, precision, recall, and F1-score
rf_report = classification_report(y_test, rf_predictions, target_names=label_encoder.classes_, output_dict=True)
svm_report = classification_report(y_test, svm_predictions, target_names=label_encoder.classes_, output_dict=True)
voting_report = classification_report(y_test, voting_predictions, target_names=label_encoder.classes_, output_dict=True)

# Save the trained models and the reports to pickle files
joblib.dump(rf_clf, 'rf_clf.pkl')
joblib.dump(svm_clf, 'svm_clf.pkl')
joblib.dump(voting_clf, 'voting_clf.pkl')
joblib.dump(label_encoder, 'label_encoder.pkl')
joblib.dump(num_imputer, 'num_imputer.pkl')
joblib.dump(rf_report, 'rf_report.pkl')
joblib.dump(svm_report, 'svm_report.pkl')
joblib.dump(voting_report, 'voting_report.pkl')
