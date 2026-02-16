import os
import sys

# Add backend to path if needed
sys.path.append(os.path.join(os.getcwd(), 'backend'))

print("Current Dir:", os.getcwd())
print("Files in root:", os.listdir('.'))
if os.path.exists('backend'):
    print("Files in backend:", os.listdir('backend'))

try:
    from flow_model_ensemble import FlowModelEnsemble
    print("ENSEMBLE_AVAILABLE: True")
    ensemble = FlowModelEnsemble()
    print("Ensemble ready:", ensemble.is_ready)
    print("Has Isolation Forest:", ensemble.has_isolation_forest)
    print("Has Random Forest:", ensemble.has_random_forest)
    print("Has GNN:", ensemble.has_gnn)
    
    if not ensemble.is_ready:
        print("Models not ready. Checking paths...")
        from flow_model_ensemble import ISO_MODEL_PATH, RF_MODEL_PATH
        print(f"ISO Path: {ISO_MODEL_PATH}, exists: {os.path.exists(ISO_MODEL_PATH)}")
        print(f"RF Path: {RF_MODEL_PATH}, exists: {os.path.exists(RF_MODEL_PATH)}")
        
except Exception as e:
    print(f"Error loading ensemble: {e}")
    import traceback
    traceback.print_exc()

try:
    import torch
    print("Torch version:", torch.__version__)
    from gnn_flow_model import GNNFlowScorer
    scorer = GNNFlowScorer()
    print("GNN Scorer ready:", scorer.is_ready)
except Exception as e:
    print(f"Error loading GNN: {e}")
