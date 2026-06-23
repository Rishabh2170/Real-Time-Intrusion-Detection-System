import joblib
import keras
import pickle
import dill
import pandas as pd
import numpy as np
import os
import tensorflow as tf

models_dir = "models"
results = {}

try:
    ae_scaler = joblib.load(os.path.join(models_dir, "preprocess_pipeline_AE_39ft.save"))
    results["AE Scaler"] = "Success"
except Exception as e:
    results["AE Scaler"] = str(e)

try:
    ae_model = keras.models.load_model(os.path.join(models_dir, 'autoencoder_39ft.hdf5'))
    results["AE Model"] = "Success"
except Exception as e:
    results["AE Model"] = str(e)

try:
    with open(os.path.join(models_dir, 'model.pkl'), 'rb') as f:
        classifier = pickle.load(f)
    results["RF Classifier"] = "Success"
except Exception as e:
    results["RF Classifier"] = str(e)

try:
    with open(os.path.join(models_dir, 'explainer'), 'rb') as f:
        explainer = dill.load(f)
    results["Explainer"] = "Success"
except Exception as e:
    results["Explainer"] = str(e)

print("--- FINAL RESULTS ---")
for k, v in results.items():
    print(f"{k}: {v}")
