try:
    import keras
except ImportError:
    from tensorflow import keras
import joblib
import pickle
import dill
import os
import tensorflow as tf

models_dir = "models"
def check_ae_scaler():
    try:
        joblib.load(os.path.join(models_dir, "preprocess_pipeline_AE_39ft.save"))
        return "OK"
    except Exception as e: return str(e)

def check_ae_model():
    try:
        keras.models.load_model(os.path.join(models_dir, 'autoencoder_39ft.hdf5'), compile=False)
        return "OK"
    except Exception as e: return str(e)

def check_rf():
    try:
        with open(os.path.join(models_dir, 'model.pkl'), 'rb') as f:
            pickle.load(f)
        return "OK"
    except Exception as e: return str(e)

def check_explainer():
    try:
        with open(os.path.join(models_dir, 'explainer'), 'rb') as f:
            dill.load(f)
        return "OK"
    except Exception as e: return str(e)

print(f"RESULT_AE_SCALER:{check_ae_scaler()}")
print(f"RESULT_AE_MODEL:{check_ae_model()}")
print(f"RESULT_RF_CLASSIFIER:{check_rf()}")
print(f"RESULT_EXPLAINER:{check_explainer()}")
