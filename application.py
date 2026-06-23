from flask_socketio import SocketIO, emit
from flask import Flask, render_template, url_for, copy_current_request_context, request, jsonify, send_file
from random import random
import random as pyrandom
from time import sleep
from threading import Thread, Event, Lock
from datetime import datetime
import os
import pickle
import math
import csv
import traceback
import json

# --- DEMO_MODE flag ---
# Force real mode: set DEMO_MODE to False to enable live packet capture
DEMO_MODE = False

# --- Optional imports ---
try:
    # scapy is only required for live packet capture. In demo mode it may be absent.
    from scapy.sendrecv import sniff
except Exception:
    sniff = None

try:
    from flow.Flow import Flow
    from flow.PacketInfo import PacketInfo
except Exception:
    # flow/PacketInfo depend on scapy; in demo mode these modules may be unavailable.
    Flow = None
    PacketInfo = None

try:
    import numpy as np
except Exception:
    np = None

try:
    import pandas as pd
except Exception:
    pd = None

try:
    import plotly
    import plotly.graph_objs
except Exception:
    plotly = None

try:
    import joblib
except Exception:
    joblib = None

try:
    import dill
except Exception:
    dill = None

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.linear_model import SGDClassifier
except Exception:
    IsolationForest = None
    SGDClassifier = None

try:
    import keras
except ImportError:
    try:
        from tensorflow import keras
    except ImportError:
        keras = None

try:
    import ipaddress
except Exception:
    ipaddress = None

try:
    from urllib.request import urlopen
except Exception:
    urlopen = None

# --- Dummy classes for demo mode ---
class DummyScaler:
    def transform(self, X):
        return X

class DummyModel:
    def predict(self, X):
        return X

# --- Placeholders for global variables ---
flow_df = None
explainer = None
predict_fn_rf = None
ae_scaler = None
ae_features = None
iso_forest = None
iso_warmup_data = [] # Buffer to train the forest on your specific network behavior
iso_warmup_limit = 300 # Wait until we have 300 'benign' flows to establish a trusted baseline
sgd_learner = None # Incremental Learner (Option 3)
sgd_buffer = [] 
sgd_limit = 1000 # Learns from every 1000 'confirmed' flows locally
# Option 2: Honey-token Tripwires (The 'Trap')
# Ports that are rarely used but often scanned by hackers
HONEY_PORTS = ['21', '23', '445', '8080', '8081', '12345']




import warnings
warnings.filterwarnings("ignore")

def ipInfo(addr=''):
    try:
        if addr == '':
            url = 'https://ipinfo.io/json'
        else:
            url = 'https://ipinfo.io/' + addr + '/json'
        res = urlopen(url)
        #response from url(if res==None then check connection)
        data = json.load(res)
        #will load the json response into data
        return data['country']
    except Exception:
        return None
__author__ = 'ravindrapal01'


app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
app.config['DEBUG'] = True

#turn the flask app into a socketio app
socketio = SocketIO(app, async_mode=None, logger=True, engineio_logger=True)

# Global state for background threads and concurrency
thread = None
thread_lock = Lock()
storage_lock = Lock()
thread_stop_event = Event()

# Logs are now handled via a safe 'Lazy-Open' strategy to bypass Windows file locks.
# Persistent log file paths:
log_file_path = "IDS_Audit_Log.csv"
input_log_path = "input_logs.csv"
 

cols = ['FlowID',
'FlowDuration',
'BwdPacketLenMax',
'BwdPacketLenMin',
'BwdPacketLenMean',
'BwdPacketLenStd',
'FlowIATMean',
'FlowIATStd',
'FlowIATMax',
'FlowIATMin',
'FwdIATTotal',
'FwdIATMean',
'FwdIATStd',
'FwdIATMax',
'FwdIATMin',
'BwdIATTotal',
'BwdIATMean',
'BwdIATStd',
'BwdIATMax',
'BwdIATMin',
'FwdPSHFlags',
'FwdPackets_s',
'MaxPacketLen',
'PacketLenMean',
'PacketLenStd',
'PacketLenVar',
'FINFlagCount',
'SYNFlagCount',
'PSHFlagCount',
'ACKFlagCount',
'URGFlagCount',
'AvgPacketSize',
'AvgBwdSegmentSize',
'InitWinBytesFwd',
'InitWinBytesBwd',
'ActiveMin',
'IdleMean',
'IdleStd',
'IdleMax',
'IdleMin',
'Src',
'SrcPort',
'Dest',
'DestPort',
'Protocol',
'FlowStartTime',
'FlowLastSeen',
'PName',
'PID',
'Classification',
'Probability',
'Risk']

def save_audit_log(row, is_raw=False):
    """
    Bulletproof Lazy-Open logging. Opens, writes, and closes immediately
    to prevent Windows 'Resource Busy' errors.
    """
    path = input_log_path if is_raw else log_file_path
    try:
        file_exists = os.path.exists(path) and os.path.getsize(path) > 0
        with open(path, 'a', newline='') as f_log:
            writer = csv.writer(f_log)
            # Add headers if it's the official audit log and it's a new file
            if not is_raw and not file_exists:
                writer.writerow(['LogTimestamp'] + cols)
            writer.writerow(row)
            f_log.flush() # Ensure it hits the disk instantly
    except Exception as e:
        print(f"Warning: Failed to save to {path} (likely locked by another app). Error: {e}")

if np is not None:
    ae_features = np.array(['FlowDuration',
    'BwdPacketLengthMax',
    'BwdPacketLengthMin',
    'BwdPacketLengthMean',
    'BwdPacketLengthStd',
    'FlowIATMean',
    'FlowIATStd',
    'FlowIATMax',
    'FlowIATMin',
    'FwdIATTotal',
    'FwdIATMean',
    'FwdIATStd',
    'FwdIATMax',
    'FwdIATMin',
    'BwdIATTotal',
    'BwdIATMean',
    'BwdIATStd',
    'BwdIATMax',
    'BwdIATMin',
    'FwdPSHFlags',
    'FwdPackets/s',
    'PacketLengthMax',
    'PacketLengthMean',
    'PacketLengthStd',
    'PacketLengthVariance',
    'FINFlagCount',
    'SYNFlagCount',
    'PSHFlagCount',
    'ACKFlagCount',
    'URGFlagCount',
    'AveragePacketSize',
    'BwdSegmentSizeAvg',
    'FWDInitWinBytes',
    'BwdInitWinBytes',
    'ActiveMin',
    'IdleMean',
    'IdleStd',
    'IdleMax',
    'IdleMin'])
else:
    ae_features = ['FlowDuration',
    'BwdPacketLengthMax',
    'BwdPacketLengthMin',
    'BwdPacketLengthMean',
    'BwdPacketLengthStd',
    'FlowIATMean',
    'FlowIATStd',
    'FlowIATMax',
    'FlowIATMin',
    'FwdIATTotal',
    'FwdIATMean',
    'FwdIATStd',
    'FwdIATMax',
    'FwdIATMin',
    'BwdIATTotal',
    'BwdIATMean',
    'BwdIATStd',
    'BwdIATMax',
    'BwdIATMin',
    'FwdPSHFlags',
    'FwdPackets/s',
    'PacketLengthMax',
    'PacketLengthMean',
    'PacketLengthStd',
    'PacketLengthVariance',
    'FINFlagCount',
    'SYNFlagCount',
    'PSHFlagCount',
    'ACKFlagCount',
    'URGFlagCount',
    'AveragePacketSize',
    'BwdSegmentSizeAvg',
    'FWDInitWinBytes',
    'BwdInitWinBytes',
    'ActiveMin',
    'IdleMean',
    'IdleStd',
    'IdleMax',
    'IdleMin']

HUMAN_MAP = {
    'BwdPacketLenMean': 'Average size of data coming back',
    'BwdPacketLenStd': 'Consistency of returning data flow',
    'BwdPacketLenMin': 'Smallest piece of data received',
    'BwdPacketLenMax': 'Largest piece of data received',
    'FwdPacketLenMean': 'Average size of data sent',
    'FwdPacketLenStd': 'Consistency of outgoing data flow',
    'FwdPacketLenMin': 'Smallest piece of data sent',
    'FwdPacketLenMax': 'Largest piece of data sent',
    'PacketLenVar': 'Traffic size variation',
    'PacketLenMean': 'Average total size of the traffic',
    'PacketLenStd': 'Standard deviation of packet lengths',
    'PacketLenMax': 'Maximum packet length observed',
    'PacketLenMin': 'Minimum packet length observed',
    'FlowDuration': 'How long the connection lasted (µs)',
    'FlowIATMean': 'Average time between messages',
    'FlowIATStd': 'Consistency of message timing',
    'FlowIATMax': 'Maximum time between any two messages',
    'FlowIATMin': 'Minimum time between any two messages',
    'FwdIATTotal': 'Total time between sent messages',
    'FwdIATMean': 'Average time between sent messages',
    'FwdIATStd': 'Consistency of sent message timing',
    'FwdIATMax': 'Longest pause between sent messages',
    'FwdIATMin': 'Shortest pause between sent messages',
    'BwdIATTotal': 'Total time between received messages',
    'BwdIATMean': 'Average time between received messages',
    'BwdIATStd': 'Consistency of received message timing',
    'BwdIATMax': 'Longest pause between received messages',
    'BwdIATMin': 'Shortest pause between received messages',
    'FwdPackets/s': 'Speed of sent packets per second',
    'BwdPackets/s': 'Speed of received packets per second',
    'FwdPSHFlags': 'Urgent data signals sent',
    'FINFlagCount': 'Total connection termination requests',
    'SYNFlagCount': 'Total connection initiation requests',
    'PSHFlagCount': 'Number of urgent data signals',
    'ACKFlagCount': 'Total confirmation signals',
    'URGFlagCount': 'Total urgent priority signals',
    'AvgPacketSize': 'Average physical size of each packet',
    'AvgBwdSegmentSize': 'Average size of received data segments',
    'AveragePacketSize': 'Average overall data packet size',
    'BwdSegmentSizeAvg': 'Average data size coming back',
    'InitWinBytesFwd': 'Initial data handshake (Sent)',
    'InitWinBytesBwd': 'Initial data handshake (Received)',
    'FWDInitWinBytes': 'Initial data handshake (Sent)',
    'BwdInitWinBytes': 'Initial data handshake (Received)',
    'ActiveMean': 'Average time the connection was active',
    'ActiveStd': 'Consistency of active periods',
    'ActiveMax': 'Longest period of continuous activity',
    'ActiveMin': 'Shortest period of continuous activity',
    'IdleMean': 'Average time the connection was idle',
    'IdleStd': 'Consistency of idle periods',
    'IdleMax': 'Longest inactive period',
    'IdleMin': 'Shortest inactive period',
    'Protocol': 'Type of Network Protocol (TCP/UDP)',
    'FlowID': 'Internal Unique Transaction Identifier',
    'Src': 'Originating Network Address',
    'SrcPort': 'Originating Service Port',
    'Dest': 'Target Network Address',
    'DestPort': 'Target Service Port',
    'FlowStartTime': 'Exact time the flow was first detected',
    'FlowLastSeen': 'Exact time of the most recent activity',
    'PName': 'Application Name responsible for flow',
    'PID': 'System Process ID',
    'PName': 'Application Name responsible for flow',
    'PID': 'System Process ID',
    'Classification': 'Models final attack/benign verdict',
    'Probability': 'Confidence score of the prediction'
}

UNIT_MAP = {
    # Time-based features (usually microseconds in CIDDS/CIC-IDS datasets)
    'FlowDuration': 'µs',
    'FlowIATMean': 'µs',
    'FlowIATStd': 'µs',
    'FlowIATMax': 'µs',
    'FlowIATMin': 'µs',
    'FwdIATTotal': 'µs',
    'FwdIATMean': 'µs',
    'FwdIATStd': 'µs',
    'FwdIATMax': 'µs',
    'FwdIATMin': 'µs',
    'BwdIATTotal': 'µs',
    'BwdIATMean': 'µs',
    'BwdIATStd': 'µs',
    'BwdIATMax': 'µs',
    'BwdIATMin': 'µs',
    'ActiveMean': 'µs',
    'ActiveStd': 'µs',
    'ActiveMax': 'µs',
    'ActiveMin': 'µs',
    'IdleMean': 'µs',
    'IdleStd': 'µs',
    'IdleMax': 'µs',
    'IdleMin': 'µs',
    
    # Size-based features (usually bytes)
    'BwdPacketLenMax': 'Bytes',
    'BwdPacketLenMin': 'Bytes',
    'BwdPacketLenMean': 'Bytes',
    'BwdPacketLenStd': 'Bytes',
    'FwdPacketLenMean': 'Bytes',
    'FwdPacketLenStd': 'Bytes',
    'FwdPacketLenMin': 'Bytes',
    'FwdPacketLenMax': 'Bytes',
    'PacketLenMax': 'Bytes',
    'PacketLenMean': 'Bytes',
    'PacketLenStd': 'Bytes',
    'PacketLenVar': 'Bytes²',
    'PacketLenMin': 'Bytes',
    'AvgPacketSize': 'Bytes',
    'AvgBwdSegmentSize': 'Bytes',
    'AveragePacketSize': 'Bytes',
    'BwdSegmentSizeAvg': 'Bytes',
    'InitWinBytesFwd': 'Bytes',
    'InitWinBytesBwd': 'Bytes',
    'FWDInitWinBytes': 'Bytes',
    'BwdInitWinBytes': 'Bytes',
    
    # Speed-based features
    'FwdPackets/s': 'Pkts/s',
    'BwdPackets/s': 'Pkts/s',
    'FwdPackets_s': 'Pkts/s', # alternate key name
}

flow_count = 0
if pd is not None:
    flow_df = pd.DataFrame(columns=cols)
else:
    # lightweight list-based storage for demo mode where pandas isn't installed
    flow_list = []


src_ip_dict = {}

current_flows = {}
FlowTimeout = 600

# load models (guarded for demo mode / missing heavy deps)
if not DEMO_MODE:
    try:
        ae_scaler = joblib.load("models/preprocess_pipeline_AE_39ft.save")
        print('Loaded AE scaler successfully')
    except Exception as e:
        print(f'Failed to load AE scaler: {e}')
        ae_scaler = None
    try:
        # Fixed: use compile=False for Keras 3 compatibility with older models
        ae_model = keras.models.load_model('models/autoencoder_39ft.hdf5', compile=False) if keras is not None else None
        print('Loaded AE model successfully')
    except Exception as e:
        print(f'Failed to load AE model: {e}')
        ae_model = None

    try:
        with open('models/model.pkl', 'rb') as f:
            classifier = pickle.load(f)
        print('Loaded RF classifier from models/model.pkl')
    except Exception as e:
        print(f'Failed to load RF classifier: {e}')
        classifier = None

    try:
        with open('models/explainer', 'rb') as f:
            explainer = dill.load(f)
        print('Loaded explainer from models/explainer')
    except Exception as e:
        print(f'Failed to load explainer: {e}')
        explainer = None

    if classifier is not None:
        predict_fn_rf = lambda x: classifier.predict_proba(x).astype(float)
    else:
        predict_fn_rf = None

# Startup diagnostics to help debug live-capture issues
try:
    print('--- Startup diagnostics ---')
    print('DEMO_MODE =', DEMO_MODE)
    print('scapy.sniff available =', callable(sniff) if sniff is not None else False)
    print('Flow module available =', Flow is not None)
    print('PacketInfo module available =', PacketInfo is not None)
    print('numpy available =', np is not None)
    print('pandas available =', pd is not None)
    print('predict_fn_rf available =', predict_fn_rf is not None)
    print('ae_model available =', ae_model is not None)
    print('ae_scaler available =', ae_scaler is not None)
    # admin check on Windows
    try:
        import ctypes
        is_admin = False
        if os.name == 'nt':
            try:
                is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
            except Exception:
                is_admin = False
        print('Running as admin (Windows):', is_admin)
    except Exception:
        pass
    print('--------------------------')
except Exception:
    pass

# Demo mode removed: this application now assumes live packet capture only.
# If model files are missing, predict_fn_rf will be None and classify() has
# a safe fallback to produce benign results so UI remains responsive.

def classify(features):
    # preprocess
    global flow_count, flow_df, flow_list
    feature_string = [str(i) for i in features[39:]]
    record = features.copy()
    # handle infinities even if numpy isn't available
    features = [math.nan if x in [math.inf, -math.inf] else float(x) for x in features[:39]]
    

    # Collect IP counts for the summary payload
    if feature_string[0] in src_ip_dict.keys():
        src_ip_dict[feature_string[0]] +=1
    else:
        src_ip_dict[feature_string[0]] = 1

    # if any NaN present in features, skip
    try:
        if any(math.isnan(x) for x in features):
            return
    except Exception:
        # if features are not numeric for some reason, skip
        return

    # features = normalisation.transform([features])
    # Safe prediction: if classifier or predict function failed to load,
    # fall back to a benign prediction so the UI continues to receive events.
    try:
        if classifier is None:
            raise Exception('classifier-missing')
        result = classifier.predict([features])
    except Exception:
        # fallback to benign result
        result = ['Benign']

    try:
        if predict_fn_rf is not None:
            proba = predict_fn_rf([features])
        else:
            raise Exception('predict_fn_missing')
    except Exception:
        # fallback probability: all mass on Benign class
        proba = [[1.0] + [0.0]*7]
    # proba can be a numpy array or a list; handle both
    first = proba[0]
    if hasattr(first, 'max'):
        proba_score = [float(first.max())]
    else:
        proba_score = [float(max(first))]
    try:
        proba_risk = float(sum(first[1:]))
    except Exception:
        proba_risk = 0.0
    # determine risk level (highest threshold first)
    # --- NEW: ISOLATION FOREST LAYER (Outlier Detection) ---
    is_outlier = False
    if IsolationForest is not None and len(features) >= 39:
        try:
            # Clean data for the forest (No NaNs)
            clean_feat = [0.0 if math.isnan(x) or math.isinf(x) else float(x) for x in features[:39]]
            
            # 1. Self-training (Warmup Phase)
            global iso_forest, iso_warmup_data
            if iso_forest is None:
                if result[0] == 'Benign': # Only learn from 'Normal' traffic
                    iso_warmup_data.append(clean_feat)
                    if len(iso_warmup_data) >= iso_warmup_limit:
                        print(f"--- AUTO-LEARNING COMPLETE: Fitting Isolation Forest with {len(iso_warmup_data)} samples ---")
                        iso_forest = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)
                        iso_forest.fit(iso_warmup_data)
                        iso_warmup_data = [] # Free up memory
            # 2. Real-time Anomaly Detection
            else:
                pred = iso_forest.predict([clean_feat])[0]
                if pred == -1: # -1 = Outlier (Anomaly)
                    is_outlier = True
        except Exception:
            pass # Fail silently for robustness

    # --- NEW: HONEY-TOKEN TRIPWIRE (Option 2) ---
    is_tripwire = False
    dest_port = str(feature_string[3]) if len(feature_string) > 3 else ''
    if dest_port in HONEY_PORTS:
        is_tripwire = True
        print(f"--- SECURITY ALERT: Honey-token Tripwire Hit on Port {dest_port} ---")

    # --- NEW: INCREMENTAL LEARNING Engine (Option 3) ---
    if SGDClassifier is not None and len(features) >= 39:
        try:
            global sgd_learner, sgd_buffer
            clean_feat = [0.0 if math.isnan(x) or math.isinf(x) else float(x) for x in features[:39]]
            
            if sgd_learner is None:
                # Initialization with first few flows
                if result[0] == 'Benign':
                    sgd_buffer.append(clean_feat)
                    if len(sgd_buffer) >= 100:
                        print("--- INITIALIZING INCREMENTAL BRAIN (SGD) ---")
                        sgd_learner = SGDClassifier(loss='modified_huber', penalty='l2', random_state=42)
                        # Establish initial classes with dummy labels
                        sgd_learner.partial_fit(sgd_buffer, ['Benign']*len(sgd_buffer), classes=['Benign', 'Attack'])
                        sgd_buffer = []
            else:
                # Study more: Learn from groups of 1000 high-confidence benign flows
                if result[0] == 'Benign' and float(proba_score[0]) > 0.95:
                    sgd_buffer.append(clean_feat)
                    if len(sgd_buffer) >= sgd_limit:
                        sgd_learner.partial_fit(sgd_buffer, ['Benign']*len(sgd_buffer))
                        sgd_buffer = []
        except Exception:
            pass

    # Determine risk (Enhanced with iForest flag + Tripwire + Incremental)
    if proba_risk > 0.8 or is_tripwire: # Instant 'High' if they hit a trap
        risk = ["<p style=\"color:red;\">High</p>"]
    elif proba_risk > 0.4 or is_outlier: 
        risk = ["<p style=\"color:orange;\">Medium</p>"]
    elif proba_risk > 0.2:
        risk = ["<p style=\"color:green;\">Low</p>"]
    else:
        risk = ["<p style=\"color:limegreen;\">Minimal</p>"]

    # x = K.process(features[0])
    # z_scores = round((x-m)/s,2)
    # p_values = norm.sf(abs(z_scores))*2


    classification = [str(result[0])]
    # print non-benign results for debugging
    try:
        if classification[0] != 'Benign':
            print(feature_string + classification + proba_score )
    except Exception:
        pass

    flow_count +=1
    # write CSV logs using Bulletproof Lazy-Open strategy
    try:
        log_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        
        # Real-time analyzed audit log
        audit_entry = [log_time, flow_count] + record + classification + proba_score + risk
        save_audit_log(audit_entry, is_raw=False)
        
        # Raw technical input log
        raw_entry = ['Flow #'+str(flow_count)] + features
        save_audit_log(raw_entry, is_raw=True)
        
    except Exception:
        print('Warning: Background logging encountered an unexpected error.', traceback.format_exc())


    # store results in pandas DataFrame if available, otherwise append to list for demo
    # Use a lock to avoid races between the background thread and HTTP handlers
    with storage_lock:
        if pd is not None:
            try:
                # ensure record is a flat list of length 39
                row = [flow_count] + record + classification + proba_score + risk
                # pad or trim to match cols length if needed
                if len(row) < len(cols):
                    row += [''] * (len(cols) - len(row))
                elif len(row) > len(cols):
                    row = row[:len(cols)]
                flow_df.loc[len(flow_df)] = row
            except Exception:
                # fallback to safe append via dict
                row_dict = {cols[i]: (row[i] if i < len(row) else '') for i in range(len(cols))}
                flow_df = pd.concat([flow_df, pd.DataFrame([row_dict])], ignore_index=True)
        else:
            # construct a dict keyed by cols for easier lookup in /flow-detail
            row = [flow_count] + record + classification + proba_score + risk
            # normalize length
            if len(row) < len(cols):
                row += [''] * (len(cols) - len(row))
            elif len(row) > len(cols):
                row = row[:len(cols)]
            row_dict = {cols[i]: row[i] for i in range(len(cols))}
            flow_list.append(row_dict)

    # build ips json
    if pd is not None:
        ip_data = {'SourceIP': list(src_ip_dict.keys()), 'count': list(src_ip_dict.values())} 
        ip_data= pd.DataFrame(ip_data)
        ip_data=ip_data.to_json(orient='records')
        ips_payload = json.loads(ip_data)
    else:
        ips_payload = [{'SourceIP': k, 'count': v} for k, v in src_ip_dict.items()]
    # Build a stable result array (fixed column order) for the front-end.
    # feature_string expected indices: 0:Src,1:SrcPort,2:Dest,3:DestPort,4:Protocol,5:FlowStartTime,6:FlowLastSeen,7:PName,8:PID
    def fs(i):
        try:
            return feature_string[i]
        except Exception:
            return ''

    safe_pname = fs(7)
    safe_pid = fs(8)
    safe_proto = fs(4)

    # ensure proba_score and risk have sensible defaults
    safe_prob = proba_score[0] if proba_score and len(proba_score) > 0 else 0.0
    safe_risk = risk[0] if risk and len(risk) > 0 else ''

    result_array = [
        flow_count,
        fs(0),
        fs(1),
        fs(2),
        fs(3),
        safe_proto,
        fs(5),
        fs(6),
        safe_pname,
        safe_pid,
        classification[0] if classification else '',
        safe_prob,
        safe_risk
    ]

    # debug print to make emits visible in server logs
    try:
        print(f"Emitting newresult Flow #{flow_count} class={classification[0]} prob={safe_prob} risk={safe_risk}")
    except Exception:
        print(f"Emitting newresult Flow #{flow_count}")
    socketio.emit('newresult', {'result': result_array, "ips": ips_payload}, namespace='/test')
    # socketio.emit('newresult', {'result': feature_string + classification}, namespace='/test')
    return [flow_count]+ record + classification+ proba_score + risk

def newPacket(pkt):
    global flow_count
    # Verbose debug for first 10 packets to confirm capture
    if flow_count < 10:
        print(f"DEBUG: Captured packet: {pkt.summary()}")

    if PacketInfo is None:
        return
    try:
        p = pkt # use 'p' for calls below
        packet = PacketInfo()
        packet.setDest(p)
        packet.setSrc(p)
        packet.setSrcPort(p)
        packet.setDestPort(p)
        packet.setProtocol(p)
        packet.setTimestamp(p)
        packet.setPSHFlag(p)
        packet.setFINFlag(p)
        packet.setSYNFlag(p)
        packet.setACKFlag(p)
        packet.setURGFlag(p)
        packet.setRSTFlag(p)
        packet.setPayloadBytes(p)
        packet.setHeaderBytes(p)
        packet.setPacketSize(p)
        packet.setWinBytes(p)
        packet.setFwdID()
        packet.setBwdID()

        #print(p[TCP].flags, packet.getFINFlag(), packet.getSYNFlag(), packet.getPSHFlag(), packet.getACKFlag(),packet.getURGFlag() )

        if packet.getFwdID() in current_flows.keys():
            flow = current_flows[packet.getFwdID()]

            # check for timeout
            # for some reason they only do it if packet count > 1
            if (packet.getTimestamp() - flow.getFlowLastSeen()) > FlowTimeout:
                classify(flow.terminated())
                del current_flows[packet.getFwdID()]
                flow = Flow(packet)
                current_flows[packet.getFwdID()] = flow

            # check for fin flag
            elif packet.getFINFlag() or packet.getRSTFlag():
                flow.new(packet, 'fwd')
                classify(flow.terminated())
                del current_flows[packet.getFwdID()]
                del flow

            else:
                flow.new(packet, 'fwd')
                current_flows[packet.getFwdID()] = flow

        elif packet.getBwdID() in current_flows.keys():
            flow = current_flows[packet.getBwdID()]

            # check for timeout
            if (packet.getTimestamp() - flow.getFlowLastSeen()) > FlowTimeout:
                classify(flow.terminated())
                del current_flows[packet.getBwdID()]
                del flow
                flow = Flow(packet)
                current_flows[packet.getFwdID()] = flow

            elif packet.getFINFlag() or packet.getRSTFlag():
                flow.new(packet, 'bwd')
                classify(flow.terminated())
                del current_flows[packet.getBwdID()]
                del flow
            else:
                flow.new(packet, 'bwd')
                current_flows[packet.getBwdID()] = flow
        else:

            flow = Flow(packet)
            current_flows[packet.getFwdID()] = flow
            # current flows put id, (new) flow

    except AttributeError:
        # not IP or TCP
        return

    except:
        traceback.print_exc()


def snif_and_detect():
    # Live-capture only: attempt to sniff packets using scapy. Do NOT generate demo flows.
    while not thread_stop_event.isSet():
        if sniff is None:
            print('scapy.sniff is not available. Ensure scapy and Npcap/WinPcap are installed. Sleeping and retrying...')
            sleep(5)
            continue

        print('--- Begin Sniffing (Thread Started) ---')
        try:
            # force scapy to use the default interface if none provided
            print('DEBUG: Calling sniff(prn=newPacket)...')
            sniff(prn=newPacket, store=0)
        except Exception as e:
            print(f'CRITICAL: Sniffing failed: {e}')
            traceback.print_exc()
            sleep(5)
            print('Sniffing exception -- ensure Npcap/WinPcap is installed and run this process with administrator privileges.')
            sleep(1)

        # classify any flows that have terminated
        for f in list(current_flows.values()):
            classify(f.terminated())


@app.route('/')
def index():
    #only by sending this page first will the client be connected to the socketio instance
    return render_template('index.html')

@app.route('/flow-detail')
def flow_detail():
    flow_id = request.args.get('flow_id', default = -1, type = int) #/flow-detail?flow_id=x
    # print(flow_id)
    if pd is not None:
        # retrieve stored row for the requested flow
        row = flow_df.loc[flow_df['FlowID'] == flow_id]
        if row.empty:
            return render_template('detail.html', tables=['<p>Flow not found</p>'], exp='<div>No explanation</div>', ae_plot='<div>No AE plot</div>', risk='')

        # Instead of generic pandas to_html, we build a structured list for premium rendering
        feature_details = []
        feature_series = row.iloc[0]
        # Iterate over all columns except 'Risk' to build the enhanced label list
        for col_name in cols:
            if col_name == 'Risk':
                continue
            
            val = feature_series[col_name]
            # Use the global HUMAN_MAP and UNIT_MAP
            desc = HUMAN_MAP.get(col_name, 'Network activity parameter')
            unit = UNIT_MAP.get(col_name, '')
            
            # Format numbers for better readability (commas for thousands)
            formatted_val = val
            if isinstance(val, (int, float)) and not math.isnan(val):
                if isinstance(val, float):
                    formatted_val = f"{val:,.2f}"
                else:
                    formatted_val = f"{val:,}"
            
            feature_details.append({
                'name': col_name,
                'value': formatted_val,
                'unit': unit,
                'description': desc
            })

        # use stored prediction/probability/risk if present; otherwise try to compute safely
        try:
            stored_class = row['Classification'].values[0]
        except Exception:
            stored_class = ''
        try:
            stored_prob = float(row['Probability'].values[0])
        except Exception:
            stored_prob = None
        try:
            stored_risk = row['Risk'].values[0]
        except Exception:
            stored_risk = ''

        # prepare explanation (only if explainer exists and predictor present)
        if explainer is not None and predict_fn_rf is not None:
            try:
                # try to fetch the original features from the DataFrame (cols 1..39)
                features_row = row.iloc[0].values[1:40]
                # sanitize inf values that were stored in 'record' before cleaning
                features_row = [math.nan if (isinstance(x, float) and (x == math.inf or x == -math.inf)) else float(x) for x in features_row]
                # LIME expects a numpy array, not a python list
                # Generate LIME explanation
                exp = None
                try:
                    # Sanitize into pure numeric list for LIME
                    clean_features = [0.0 if (math.isnan(x) or x == math.inf or x == -math.inf) else float(x) for x in features_row]
                    feat_array = np.array(clean_features)
                    
                    # Predict first to know which class to explain
                    pred_class = int(predict_fn_rf(feat_array.reshape(1, -1))[0].argmax())
                    
                    # Explain specifically the predicted class to avoid label mismatch
                    exp = explainer.explain_instance(feat_array, predict_fn_rf, labels=(pred_class,), num_features=6)
                except Exception as e:
                    print("--- LIME Fail Traceback ---")
                    traceback.print_exc()
                    print(f"LIME calculation failed with message: {e}")
                    exp = None

                if exp is not None:
                    # Map the predicted class name for the UI
                    class_labels = ['Benign', 'Botnet', 'DDoS', 'DoS', 'FTP-Patator', 'Probe', 'SSH-Patator', 'Web Attack']
                    pred_class_name = class_labels[pred_class]
                    
                    # Custom high-fidelity Plotly visualization for LIME explanation
                    lime_list = exp.as_list(label=pred_class)
                    feat_names = [x[0] for x in lime_list]
                    feat_weights = [x[1] for x in lime_list]
                    
                    # Create a professional contribution chart
                    lime_fig = plotly.graph_objs.Figure()
                    lime_fig.add_trace(plotly.graph_objs.Bar(
                        x=feat_weights,
                        y=feat_names,
                        orientation='h',
                        marker=dict(
                            color=feat_weights,
                            colorscale='RdBu', # Blue for Benign, Red for Malicious
                            cmid=0,
                            line=dict(color='white', width=1)
                        ),
                        # Hover shows the feature, the value, and exactly WHICH attack it is supporting
                        hovertemplate="<b>Feature</b>: %{y}<br><b>Contribution</b>: %{x:.4f}<br><b>Supports</b>: " + pred_class_name + "<extra></extra>"
                    ))
                    
                    # Human-friendly translation for common network features
                    # Use the global HUMAN_MAP instead of the local one
                    human_map = HUMAN_MAP
                    
                    # Create styled Y-axis labels: Technical Name <br> (Human Description)
                    styled_feat_names = []
                    for raw_feat in feat_names:
                        clean_name = raw_feat.split(' ')[0] if ' ' in raw_feat else raw_feat
                        desc = human_map.get(clean_name, 'Network activity pattern')
                        styled_feat_names.append(f"{raw_feat}<br><span style='font-size:10px; color:gray;'>({desc})</span>")
                    
                    # Also use the top feature for the main title reasoning
                    top_raw_feat = feat_names[0]
                    top_clean_name = top_raw_feat.split(' ')[0] if ' ' in top_raw_feat else top_raw_feat
                    top_human_desc = human_map.get(top_clean_name, 'This network characteristic')
                    
                    # Build the human reason string for the title
                    if '<' in top_raw_feat:
                        human_reason = f"{top_human_desc} was very small"
                    elif '>' in top_raw_feat:
                        human_reason = f"{top_human_desc} was very large"
                    else:
                        human_reason = f"{top_human_desc} matched a specific pattern"

                    # Add a simple conclusion paragraph for non-tech users
                    if pred_class_name == 'Benign':
                        conclusion = "Everything looks normal. The data is flowing at a steady, safe rate with no signs of malicious activity."
                    else:
                        conclusion = f"This traffic is suspicious. It matches known <b>{pred_class_name}</b> attack patterns, behaving differently from regular user traffic."

                    lime_fig = plotly.graph_objs.Figure()
                    lime_fig.add_trace(plotly.graph_objs.Bar(
                        x=feat_weights,
                        y=styled_feat_names, # Use the new dual-line labels
                        orientation='h',
                        marker=dict(
                            color=feat_weights,
                            colorscale='RdBu',
                            cmid=0,
                            line=dict(color='white', width=1)
                        ),
                        hovertemplate="<b>Feature</b>: %{y}<br><b>Contribution</b>: %{x:.4f}<br><b>Supports</b>: " + pred_class_name + "<extra></extra>"
                    ))
                    
                    lime_fig.update_layout(
                        title=dict(
                            text=f"Why the Model predicted: <b>{pred_class_name}</b><br><span style='font-size:12px; color:gray;'>(Primary Reason: {top_raw_feat} - <i>{human_reason}</i>)</span><br><span style='font-size:13px; color:#333;'><b>Summary:</b> {conclusion}</span>",
                            x=0.05,
                            y=0.9
                        ),
                        xaxis_title="Contribution (Supports Attack vs Supports Benign)",
                        template="plotly_white",
                        margin=dict(l=150, r=10, t=110, b=10), # Extra left margin for the descriptive labels
                        height=550,
                        showlegend=False
                    )
                    
                    # Generate the final Plotly HTML (Top percentages removed as requested)
                    exp_html = plotly.offline.plot(lime_fig, include_plotlyjs=False, output_type='div')
                else:
                    exp_html = '<div>LIME explanation currently unavailable for this flow</div>'
            except Exception as e:
                exp_html = f'<div>No explanation available (error: {e})</div>'
        else:
            exp_html = '<div>No explanation available</div>'

        # Instead of the technical AE plot, we build a aesthetic Connection Signature (fingerprint)
        signature_data = {
            'identity': [
                {'label': 'Source Address', 'value': row.iloc[0]['Src']},
                {'label': 'Target Address', 'value': row.iloc[0]['Dest']},
                {'label': 'Application Name', 'value': row.iloc[0]['PName']},
                {'label': 'Process ID (PID)', 'value': row.iloc[0]['PID']}
            ],
            'traffic_dna': [
                {'label': 'Total Messages', 'value': f"{int(row.iloc[0].get('TotalFwdPackets', 0)) + int(row.iloc[0].get('TotalBwdPackets', 0)):,} Pkts"},
                {'label': 'Flow Duration', 'value': f"{row.iloc[0]['FlowDuration']:,} µs"},
                {'label': 'Packet Speed', 'value': f"{float(row.iloc[0]['FwdPackets_s']):,.2f} Pkts/s"},
                {'label': 'Protocol Type', 'value': 'TCP' if row.iloc[0]['Protocol'] == '6' else 'UDP' if row.iloc[0]['Protocol'] == '17' else row.iloc[0]['Protocol']}
            ],
            'handshake': [
                {'label': 'Fwd Initial Win', 'value': f"{int(row.iloc[0]['InitWinBytesFwd']):,} Bytes"},
                {'label': 'Bwd Initial Win', 'value': f"{int(row.iloc[0]['InitWinBytesBwd']):,} Bytes"},
                {'label': 'Dest Port', 'value': row.iloc[0]['DestPort']},
                {'label': 'Src Port', 'value': row.iloc[0]['SrcPort']}
            ],
            'timing': [
                {'label': 'Avg Pause', 'value': f"{float(row.iloc[0]['FlowIATMean']):,.2f} µs"},
                {'label': 'Timing Jitter', 'value': f"{float(row.iloc[0]['FlowIATStd']):,.2f} µs"},
                {'label': 'Max Hold', 'value': f"{float(row.iloc[0]['FlowIATMax']):,.2f} µs"},
                {'label': 'Min Hold', 'value': f"{float(row.iloc[0]['FlowIATMin']):,.2f} µs"}
            ]
        }

        return render_template('detail.html', feature_details=feature_details, exp=exp_html, signature=signature_data, risk=stored_risk)
    else:
        # demo mode: use flow_list (simple in-memory storage) and return lightweight detail page
        flow = next((f for f in flow_list if f['FlowID'] == flow_id), None)
        if flow is None:
            return render_template('detail.html', tables=['<p>Flow not found (demo)</p>'], exp='<div>No explanation</div>', ae_plot='<div>No AE plot</div>', risk='')
        # demo mode: build feature_details list manually from the dict
        feature_details = []
        for col in cols:
            if col == 'Risk':
                continue
            val = flow.get(col, '')
            desc = HUMAN_MAP.get(col, 'Network activity parameter')
            unit = UNIT_MAP.get(col, '')
            
            # Format numbers for better readability
            formatted_val = val
            try:
                num_val = float(val)
                if num_val.is_integer():
                    formatted_val = f"{int(num_val):,}"
                else:
                    formatted_val = f"{num_val:,.2f}"
            except (ValueError, TypeError):
                pass

            feature_details.append({
                'name': col,
                'value': formatted_val,
                'unit': unit,
                'description': desc
            })
        # attempt to produce explanation only if explainer and predict function are available
        if explainer is not None and predict_fn_rf is not None:
            try:
                # try to uses zeros if np is available as a fallback
                fallback_feat = np.zeros(39) if np is not None else [0.0]*39
                exp_obj = explainer.explain_instance(fallback_feat, predict_fn_rf)
                exp_html = exp_obj.as_html() if hasattr(exp_obj, 'as_html') else str(exp_obj)
            except Exception:
                exp_html = '<div>No explanation available</div>'
        else:
            exp_html = '<div>No explanation available</div>'
        return render_template('detail.html', feature_details=feature_details, exp=exp_html, signature=None, risk=flow.get('Risk', ''))


@app.route('/flows/status')
def flows_status():
    """Return simple JSON status for flows - useful for monitoring and smoke tests."""
    with storage_lock:
        total_emitted = flow_count
        stored = len(flow_df) if pd is not None else len(flow_list)
    return jsonify({'emitted': total_emitted, 'stored': stored})

# @app.route('/flow-detail')
# def flow_detail():
#     flow_id = request.args.get('flow_id', default = -1, type = int) #/flow-detail?flow_id=x
#     flow = flow_df.loc[flow_df['FlowID'] == flow_id].values[1:40]
#     print(flow)
#     print(type(flow))
#     X = normalisation.transform([flow])
#     explainer = lime.lime_tabular.LimeTabularExplainer(X,feature_names = cols, class_names=['Benign' 'Botnet' 'DDoS' 'DoS' 'FTP-Patator' 'Probe' 'SSH-Patator','Web Attack'],kernel_width=5)

#     choosen_instance = X
#     exp = explainer.explain_instance(choosen_instance, predict_fn_rf,num_features=10)
#     # exp.show_in_notebook(show_all=False)




@socketio.on('connect', namespace='/test')
def test_connect():
    global thread
    print('DEBUG: SocketIO Client connected (Namespace: /test)')
    with thread_lock:
        if thread is None:
            print("DEBUG: Starting snif_and_detect background task...")
            thread = socketio.start_background_task(snif_and_detect)

    #Start the random result generator thread only if the thread has not been started before.
    if not thread.is_alive():
        print("Starting Thread")
        thread = socketio.start_background_task(snif_and_detect)

@socketio.on('disconnect', namespace='/test')
def test_disconnect():
    print('Client disconnected')


@app.route('/download-logs')
def download_logs():
    """Allows secure download of the CSV audit trail from the UI"""
    try:
        if os.path.exists(log_file_path):
            return send_file(log_file_path, as_attachment=True)
        else:
            return "Log file empty or not yet generated.", 404
    except Exception as e:
        return f"Download failed: {str(e)}", 500

if __name__ == '__main__':
    socketio.run(app)
