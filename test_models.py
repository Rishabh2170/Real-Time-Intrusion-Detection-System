import joblib
import keras
import pickle
import dill
import pandas as pd
import numpy as np
import os
import tensorflow as tf

print(f"Pandas version: {pd.__version__ if pd is not None else 'None'}")
print(f"Numpy version: {np.__version__ if np is not None else 'None'}")
print(f"Keras version: {keras.__version__ if keras is not None else 'None'}")
print(f"Tensorflow version: {tf.__version__}")

models_dir = "models"

try:
    ae_scaler = joblib.load(os.path.join(models_dir, "preprocess_pipeline_AE_39ft.save"))
    print("AE Scaler loaded successfully")
except Exception as e:
    print(f"Failed to load AE Scaler: {e}")

try:
    # Use standard keras loading
    ae_model = keras.models.load_model(os.path.join(models_dir, 'autoencoder_39ft.hdf5'))
    print("AE Model loaded successfully")
except Exception as e:
    print(f"Failed to load AE Model: {e}")

try:
    with open(os.path.join(models_dir, 'model.pkl'), 'rb') as f:
        classifier = pickle.load(f)
    print("RF Classifier loaded successfully")
except Exception as e:
    print(f"Failed to load RF Classifier: {e}")

try:
    with open(os.path.join(models_dir, 'explainer'), 'rb') as f:
        explainer = dill.load(f)
    print("Explainer loaded successfully")
except Exception as e:
    print(f"Failed to load Explainer: {e}")
