#!/usr/bin/env python3
"""
ONNX Model Conversion and Performance Testing
Converts XGBoost and scikit-learn models to ONNX format for faster inference
"""

import os
import sys
import time
import numpy as np
import joblib
import xgboost as xgb
import json

# ONNX conversion libraries
try:
    import onnx
    import onnxruntime as ort
    from skl2onnx import convert_sklearn, update_registered_converter
    from skl2onnx.common.data_types import FloatTensorType as SklearnFloatTensorType
    from skl2onnx.common.shape_calculator import calculate_linear_classifier_output_shapes
    import onnxmltools
    from onnxmltools.convert import convert_xgboost as convert_xgb
    from onnxmltools.convert.common.data_types import FloatTensorType as XGBFloatTensorType
    from onnxmltools.convert.xgboost.operator_converters.XGBoost import convert_xgboost
except ImportError as e:
    print(f"ERROR: Missing ONNX dependencies: {e}")
    print("\nInstall with:")
    print("  pip install onnx onnxruntime skl2onnx onnxmltools")
    sys.exit(1)


def patch_xgboost_converter():
    """
    Monkey-patch onnxmltools to handle XGBoost 3.0's string-encoded arrays.
    XGBoost 3.0 stores multi-class base_score and other attributes as JSON string arrays.
    """
    import onnxmltools.convert.xgboost.operator_converters.XGBoost as xgb_converter
    
    original_float = float
    
    def safe_float(value):
        """Convert value to float, handling JSON string arrays"""
        if isinstance(value, str):
            value = value.strip()
            if value.startswith('[') and value.endswith(']'):
                try:
                    parsed = json.loads(value)
                    if isinstance(parsed, list) and len(parsed) > 0:
                        return original_float(parsed[0])
                except (json.JSONDecodeError, ValueError):
                    pass
        return original_float(value)
    
    # Patch the builtins in the xgboost converter module
    xgb_converter.float = safe_float
    
    print("✓ Patched onnxmltools for XGBoost 3.0 compatibility")


# Apply the patch at import time
patch_xgboost_converter()


class ONNXConverter:
    """Convert ML models to ONNX format"""

    def __init__(self, models_dir="models"):
        self.models_dir = models_dir

    def convert_xgb_to_joblib(self, xgb_path, joblib_path, num_classes=16):
        """Convert .xgb file to .joblib format for better compatibility"""
        print(f"Converting {xgb_path} to joblib format...")
        
        # Load the booster
        booster = xgb.Booster()
        booster.load_model(xgb_path)
        
        # Export to JSON and fix problematic fields
        import tempfile
        import json
        
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False, mode='w') as tmp:
            tmp_json_path = tmp.name
        
        booster.save_model(tmp_json_path)
        
        # Read the JSON
        with open(tmp_json_path, 'r') as f:
            model_json = json.load(f)
        
        def fix_string_arrays(obj, path=""):
            """Recursively find and fix string-encoded arrays"""
            if isinstance(obj, dict):
                for key, value in obj.items():
                    current_path = f"{path}.{key}" if path else key
                    if isinstance(value, str) and value.startswith('[') and value.endswith(']'):
                        try:
                            parsed = json.loads(value)
                            if isinstance(parsed, list) and len(parsed) > 0:
                                # Convert array to first element (scalar)
                                obj[key] = str(parsed[0])
                                print(f"   Fixed: {current_path} (array of {len(parsed)} -> scalar)")
                        except json.JSONDecodeError:
                            pass
                    elif isinstance(value, (dict, list)):
                        fix_string_arrays(value, current_path)
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    fix_string_arrays(item, f"{path}[{i}]")
        
        print("Fixing XGBoost 3.0 string-encoded arrays...")
        fix_string_arrays(model_json)
        
        # Save fixed JSON
        fixed_json_path = tmp_json_path + '.fixed.json'
        with open(fixed_json_path, 'w') as f:
            json.dump(model_json, f)
        
        # Create fresh booster from fixed JSON
        clean_booster = xgb.Booster()
        clean_booster.load_model(fixed_json_path)
        
        # Clean up temp files
        os.remove(tmp_json_path)
        os.remove(fixed_json_path)
        
        # Create XGBClassifier and attach the clean booster
        classifier = xgb.XGBClassifier(n_estimators=300, use_label_encoder=False, objective='multi:softprob', num_class=num_classes)
        classifier._Booster = clean_booster
        classifier.n_classes_ = num_classes
        classifier._le = None
        # Set required sklearn attributes using __dict__ to bypass property
        classifier.__dict__['classes_'] = np.array(list(range(num_classes)))
        classifier.__dict__['n_features_in_'] = 50
        classifier.__dict__['_fitted'] = True
        
        # Save as joblib
        joblib.dump(classifier, joblib_path)
        print(f"✅ Saved: {joblib_path}")
        return joblib_path

    def convert_xgboost(self, input_path, output_path, num_features=100):
        """Convert XGBoost model to ONNX"""
        print(f"\n{'='*60}")
        print(f"Converting XGBoost: {input_path}")
        print(f"{'='*60}")

        # Load XGBoost model and analyze
        print("Loading XGBoost model...")
        
        booster = xgb.Booster()
        booster.load_model(input_path)

        print(f"Converting to ONNX (features: {num_features})...")
        
        # Check model structure
        import json
        import tempfile
        
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False, mode='w') as tmp:
            tmp_json_path = tmp.name
        booster.save_model(tmp_json_path)
        
        with open(tmp_json_path, 'r') as f:
            model_json = json.load(f)
        os.remove(tmp_json_path)
        
        objective = model_json.get('learner', {}).get('objective', {})
        num_class = int(model_json.get('learner', {}).get('learner_model_param', {}).get('num_class', '2'))
        
        print(f"   Objective: {objective.get('name', 'unknown')}")
        print(f"   Number of classes: {num_class}")
        
        try:
            # Create fixed XGBClassifier wrapper
            joblib_path = input_path.replace('.xgb', '_fixed.joblib')
            
            # Force recreate to apply fixes
            if os.path.exists(joblib_path):
                os.remove(joblib_path)
            
            self.convert_xgb_to_joblib(input_path, joblib_path, num_classes=num_class)
            model = joblib.load(joblib_path)

            # Register XGBoost converter with skl2onnx
            update_registered_converter(
                xgb.XGBClassifier,
                'XGBoostXGBClassifier',
                calculate_linear_classifier_output_shapes,
                convert_xgboost,
                options={'nocl': [True, False], 'zipmap': [True, False, 'columns']}
            )

            # Define input type using sklearn FloatTensorType
            initial_type = [('float_input', SklearnFloatTensorType([None, num_features]))]

            # Patch float globally during conversion to handle XGBoost 3.0 string arrays
            import builtins
            original_float = builtins.float
            
            def patched_float(value):
                if isinstance(value, str):
                    value_stripped = value.strip()
                    if value_stripped.startswith('[') and value_stripped.endswith(']'):
                        try:
                            parsed = json.loads(value_stripped)
                            if isinstance(parsed, list) and len(parsed) > 0:
                                return original_float(parsed[0])
                        except (json.JSONDecodeError, ValueError):
                            pass
                return original_float(value)
            
            builtins.float = patched_float
            
            try:
                # Convert to ONNX
                onnx_model = convert_sklearn(
                    model, 
                    initial_types=initial_type,
                    target_opset={'': 17, 'ai.onnx.ml': 3}
                )
            finally:
                # Restore original float
                builtins.float = original_float

            # Save ONNX model
            with open(output_path, "wb") as f:
                f.write(onnx_model.SerializeToString())

            print(f"✅ Saved ONNX model: {output_path}")

            # Get file sizes
            original_size = os.path.getsize(input_path) / 1024
            onnx_size = os.path.getsize(output_path) / 1024
            print(f"   Original: {original_size:.2f} KB")
            print(f"   ONNX:     {onnx_size:.2f} KB")
            print(f"   Ratio:    {onnx_size/original_size:.2f}x")

            return output_path

        except Exception as e:
            print(f"❌ Conversion failed: {e}")
            return None

    def convert_sklearn(self, input_path, output_path, num_features=100):
        """Convert scikit-learn model to ONNX"""
        print(f"\n{'='*60}")
        print(f"Converting scikit-learn: {input_path}")
        print(f"{'='*60}")

        # Load sklearn model
        print("Loading scikit-learn model...")
        model = joblib.load(input_path)

        # Define input type
        initial_type = [('float_input', SklearnFloatTensorType([None, num_features]))]

        # Convert to ONNX
        print(f"Converting to ONNX (features: {num_features})...")
        try:
            onnx_model = convert_sklearn(
                model, 
                initial_types=initial_type,
                target_opset={'': 17, 'ai.onnx.ml': 3}
            )

            # Save ONNX model
            with open(output_path, "wb") as f:
                f.write(onnx_model.SerializeToString())

            print(f"✅ Saved ONNX model: {output_path}")

            # Get file sizes
            original_size = os.path.getsize(input_path) / 1024
            onnx_size = os.path.getsize(output_path) / 1024
            print(f"   Original: {original_size:.2f} KB")
            print(f"   ONNX:     {onnx_size:.2f} KB")
            print(f"   Ratio:    {onnx_size/original_size:.2f}x")

            return output_path

        except Exception as e:
            print(f"❌ Conversion failed: {e}")
            return None

    def test_onnx_inference(self, onnx_path, num_features=100, iterations=1000):
        """Test ONNX model inference performance"""
        print(f"\n{'='*60}")
        print(f"Testing ONNX Model: {onnx_path}")
        print(f"{'='*60}")

        # Load ONNX model
        print("Loading ONNX model...")
        try:
            session = ort.InferenceSession(onnx_path)
        except Exception as e:
            print(f"❌ Failed to load ONNX model: {e}")
            return None

        input_name = session.get_inputs()[0].name
        output_names = [output.name for output in session.get_outputs()]

        print(f"Input: {input_name}")
        print(f"Outputs: {output_names}")

        # Generate random test data
        print(f"\nGenerating {iterations} random test samples...")
        test_data = np.random.rand(iterations, num_features).astype(np.float32)

        # Warmup
        print("Warming up...")
        for _ in range(10):
            session.run(output_names, {input_name: test_data[0:1]})

        # Benchmark
        print(f"\nRunning {iterations} predictions...")
        latencies = []

        for i in range(iterations):
            start = time.perf_counter()
            result = session.run(output_names, {input_name: test_data[i:i+1]})
            latency = (time.perf_counter() - start) * 1000  # ms
            latencies.append(latency)

        # Statistics
        latencies = np.array(latencies)

        print(f"\n{'='*60}")
        print("PERFORMANCE RESULTS")
        print(f"{'='*60}")
        print(f"Total predictions: {iterations}")
        print(f"Total time:        {sum(latencies)/1000:.2f}s")
        print(f"Throughput:        {iterations/(sum(latencies)/1000):.2f} req/s")
        print(f"\nLatency Metrics:")
        print(f"  Average:   {np.mean(latencies):.3f}ms")
        print(f"  Median:    {np.median(latencies):.3f}ms")
        print(f"  Min:       {np.min(latencies):.3f}ms")
        print(f"  Max:       {np.max(latencies):.3f}ms")
        print(f"  P50:       {np.percentile(latencies, 50):.3f}ms")
        print(f"  P95:       {np.percentile(latencies, 95):.3f}ms ✅ (Target: <5ms)")
        print(f"  P99:       {np.percentile(latencies, 99):.3f}ms")

        # Check target
        p95 = np.percentile(latencies, 95)
        if p95 < 5.0:
            print(f"\n✅ TARGET MET: P95 latency {p95:.3f}ms < 5ms")
        else:
            print(f"\n⚠️  TARGET MISSED: P95 latency {p95:.3f}ms > 5ms")

        return {
            'mean': np.mean(latencies),
            'p50': np.percentile(latencies, 50),
            'p95': np.percentile(latencies, 95),
            'p99': np.percentile(latencies, 99),
            'throughput': iterations/(sum(latencies)/1000)
        }

    def convert_all_models(self):
        """Convert all models in the models directory"""
        print("\n" + "="*60)
        print("MIRAGE WAF - ONNX Model Conversion")
        print("="*60)

        models = {
            'http_classifier.xgb': {
                'type': 'xgboost',
                'output': 'http_classifier.onnx',
                'features': 50  # HTTP models use 50 features
            },
            'http_isolation_forest.joblib': {
                'type': 'sklearn',
                'output': 'http_isolation_forest.onnx',
                'features': 50
            },
            'http_scaler.joblib': {
                'type': 'sklearn',
                'output': 'http_scaler.onnx',
                'features': 50
            }
        }

        results = {}

        for model_file, config in models.items():
            input_path = os.path.join(self.models_dir, model_file)
            output_path = os.path.join(self.models_dir, config['output'])

            # Check if model exists
            if not os.path.exists(input_path):
                print(f"\n⚠️  Skipping {model_file} (not found)")
                continue

            # Convert based on type
            if config['type'] == 'xgboost':
                onnx_path = self.convert_xgboost(
                    input_path,
                    output_path,
                    num_features=config['features']
                )
            elif config['type'] == 'sklearn':
                onnx_path = self.convert_sklearn(
                    input_path,
                    output_path,
                    num_features=config['features']
                )

            # Test if conversion succeeded
            if onnx_path:
                perf = self.test_onnx_inference(
                    onnx_path,
                    num_features=config['features'],
                    iterations=1000
                )
                results[model_file] = perf

        # Summary
        print("\n" + "="*60)
        print("CONVERSION SUMMARY")
        print("="*60)

        for model_file, perf in results.items():
            if perf:
                print(f"\n{model_file}:")
                print(f"  ✅ Converted to ONNX")
                print(f"  P95 latency: {perf['p95']:.3f}ms")
                print(f"  Throughput:  {perf['throughput']:.0f} req/s")

        print("\n" + "="*60)
        print("Next Steps:")
        print("="*60)
        print("1. Update ml/secure_inference.py to use ONNX models")
        print("2. Test with: python3 tests/test_ml_model.py")
        print("3. Benchmark with: python3 ml/performance_optimizer.py")
        print("4. Deploy: docker-compose -f docker-compose.production.yml up -d")


def main():
    """Main conversion script"""
    import argparse

    # Get the root directory (parent of the ml folder where this script is located)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    root_dir = os.path.dirname(script_dir)
    default_models_dir = os.path.join(root_dir, 'models')

    parser = argparse.ArgumentParser(description='Convert ML models to ONNX format')
    parser.add_argument('--models-dir', default=default_models_dir, help='Directory containing models')
    parser.add_argument('--model', help='Convert specific model file')
    parser.add_argument('--test-only', help='Test existing ONNX model')
    parser.add_argument('--features', type=int, default=100, help='Number of features')
    parser.add_argument('--iterations', type=int, default=1000, help='Test iterations')

    args = parser.parse_args()

    converter = ONNXConverter(models_dir=args.models_dir)

    if args.test_only:
        # Test existing ONNX model
        converter.test_onnx_inference(
            args.test_only,
            num_features=args.features,
            iterations=args.iterations
        )
    elif args.model:
        # Convert specific model
        input_path = os.path.join(args.models_dir, args.model)
        output_path = input_path.replace('.xgb', '.onnx').replace('.joblib', '.onnx')

        if args.model.endswith('.xgb'):
            converter.convert_xgboost(input_path, output_path, num_features=args.features)
        elif args.model.endswith('.joblib'):
            converter.convert_sklearn(input_path, output_path, num_features=args.features)

        # Test
        converter.test_onnx_inference(output_path, num_features=args.features)
    else:
        # Convert all models
        converter.convert_all_models()


if __name__ == "__main__":
    main()
