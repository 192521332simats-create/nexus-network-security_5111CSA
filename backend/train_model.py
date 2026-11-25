
import pandas as pd
import joblib
from pathlib import Path

from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "datasets"

train_file = DATA_DIR / "UNSW_NB15_training-set.csv"
test_file = DATA_DIR / "UNSW_NB15_testing-set.csv"

print("Loading datasets...", flush=True)

train_df = pd.read_csv(train_file)
test_df = pd.read_csv(test_file)

print("Original training:", train_df.shape, flush=True)
print("Original testing:", test_df.shape, flush=True)

target = "attack_cat"

if target not in train_df.columns or target not in test_df.columns:
    raise ValueError("attack_cat column not found.")

# Smaller representative samples
train_df = train_df.groupby(target, group_keys=False).apply(
    lambda group: group.sample(
        n=min(len(group), 3000), random_state=42
    )
).reset_index(drop=True)

test_df = test_df.groupby(target, group_keys=False).apply(
    lambda group: group.sample(
        n=min(len(group), 1000), random_state=42
    )
).reset_index(drop=True)

print("Reduced training:", train_df.shape, flush=True)
print("Reduced testing:", test_df.shape, flush=True)

drop_columns = [target, "label", "id"]

X_train = train_df.drop(
    columns=[c for c in drop_columns if c in train_df.columns]
)
y_train = train_df[target].fillna("Unknown").astype(str)

X_test = test_df.drop(
    columns=[c for c in drop_columns if c in test_df.columns]
)
y_test = test_df[target].fillna("Unknown").astype(str)

common_columns = [
    c for c in X_train.columns if c in X_test.columns
]
X_train = X_train[common_columns]
X_test = X_test[common_columns]

numeric_columns = X_train.select_dtypes(
    include=["number"]
).columns.tolist()

categorical_columns = [
    c for c in common_columns if c not in numeric_columns
]

preprocessor = ColumnTransformer([
    ("numeric", SimpleImputer(strategy="median"), numeric_columns),
    ("categorical", Pipeline([
        ("imputer", SimpleImputer(strategy="most_frequent")),
        ("encoder", OneHotEncoder(handle_unknown="ignore"))
    ]), categorical_columns)
])

model = Pipeline([
    ("preprocessing", preprocessor),
    ("classifier", RandomForestClassifier(
        n_estimators=20,
        max_depth=12,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced"
    ))
])

print("Training faster Random Forest model...", flush=True)
model.fit(X_train, y_train)

print("Testing model...", flush=True)
predictions = model.predict(X_test)

accuracy = accuracy_score(y_test, predictions)

print("\nModel Accuracy:", round(accuracy * 100, 2), "%")
print("\nClassification Report:")
print(classification_report(
    y_test, predictions, zero_division=0
))

model_path = BASE_DIR / "random_forest_model.joblib"
joblib.dump(model, model_path)

print("\nModel saved successfully:", model_path, flush=True)
