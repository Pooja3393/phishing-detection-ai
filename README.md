# PhishGuard Phishing Detection Dashboard

The Streamlit dashboard includes a home screen with URL, QR, and screenshot scan cards; a dark navigation sidebar; latest results, key findings, and session scan history. PhishGuard extracts URL signals, applies a local phishing classifier, checks whether a public destination responds, and sends decoded QR destinations through the same URL pipeline. The screenshot classifier remains a research baseline.

## Run

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
python -m pip install -r requirements.txt
streamlit run streamlit_app/app.py
```

URL and QR scanning work without an OpenAI key. To enable optional GPT-6 explanations, copy `.env.example` to `.env` and set `OPENAI_API_KEY`; the app reads `.env` at startup. `OPENAI_MODEL` defaults to `gpt-6-luna`; `OPENAI_REASONING_EFFORT` defaults to `low`.

## User accounts and scan history

The app includes account creation, login, and logout. Scan history is stored in a local SQLite database at `data/phishguard.sqlite3`, linked to the signed-in account, and loaded again after the user logs back in. Passwords are stored as salted PBKDF2 hashes, not plain text. Keep the `data/` directory private and backed up. This local SQLite setup is intended for a single app host; a multi-instance deployment should use a secured shared database and production-grade identity provider over HTTPS.

When an OpenAI key is configured, the scanned URL/destination and its result fields are sent to OpenAI to write the optional explanation. Leave the key unset to keep explanations local/off while retaining URL and QR analysis.

## Upload your CSV and train a model

Dataset training is locked by default so app users cannot replace the active model. To train as the owner, copy `.env.example` to `.env`, set a private `PHISHGUARD_ADMIN_PASSWORD`, restart the app, open **Upload Dataset**, and unlock training with that password. Do not commit or share `.env`. Users without the password can continue scanning but cannot upload or activate a model.

After unlocking, upload a CSV containing the 30 named URL features from the legacy phishing dataset plus one binary label column named `class`, `label`, `target`, `is_phishing`, or `phishing`. An extra `Index` column is fine. Feature values must be numeric `-1`, `0`, or `1`. At least 10 examples from each class are needed. Select which label means phishing. Training activates a new user model; keep a backup of `models/phishing_model_user.pkl` before replacing a model you want to retain.

The app trains two tree classifiers, selects one using a separate validation split, then reports precision, recall, F1, balanced accuracy, coverage, and a held-out confusion matrix. The held-out set is not used to select the model. Predictions with mixed probabilities are reported as **inconclusive**. The uploaded model is saved as `models/phishing_model_user.pkl` and becomes active; the bundled model remains in `models/phishing_model.pkl`.

To reduce HTTPS-driven false positives, the uploaded model is trained without the `HTTPS` feature. The application still reports HTTP as a transport concern, but HTTP alone does not add phishing risk points. The bundled historical model does include HTTPS; when its verdict changes after neutralizing that feature, PhishGuard reports the result as inconclusive.

The same trainer is available from the command line: `python src/train_model.py path/to/data.csv --phishing-label -1` (replace `-1` with the actual label value in your file).

## Dataset expectations and limitations

The ZIP includes a pretrained model but **does not include its training CSV**. Its training source, class balance, and independent test metrics therefore cannot be verified from this archive. Upload the labeled dataset you trust and review its held-out metrics before relying on its predictions. A random row split can overstate performance when near-duplicate URLs or sites occur in both the training and test rows; for serious evaluation, split by domain and test on a later time period.

The 30-feature legacy format contains site and reputation features that are not reliably available from a URL alone. PhishGuard marks several unavailable values unknown rather than inventing them, but a model trained on a different feature extraction process may still behave poorly. Treat the classifier as one signal. A low risk result is not a guarantee of safety. HTTP now adds a modest transport-risk score and warning; account/verification wording and reserved test domains add contextual signals, not automatic phishing verdicts.

### Fixing `cv2.HOGDescriptor` on Windows

The screenshot model requires the standard `opencv-python` package. Activate the project's `.venv`, then run:

```powershell
python -m pip uninstall -y opencv-python opencv-python-headless opencv-contrib-python opencv-contrib-python-headless
python -m pip install --no-cache-dir -r requirements.txt
```

Restart Streamlit after installation. Do not install multiple OpenCV variants into the same environment; they all provide the `cv2` module and can overwrite one another.

The scanner blocks local/private network destinations and rechecks redirect hosts before requesting them. It performs bounded public HTTP requests to extract page signals. Do not scan URLs you are not authorized to analyze.

## Project components

- `src/feature_extractor.py`: URL features and bounded page-signal extraction.
- `src/predict_url.py`: model loading, probability thresholds, and inconclusive verdicts.
- `src/risk_engine.py`: rule-based score with an HTTP transport warning and cautious URL-context signals.
- `src/drift_verifier.py`: active-link response check.
- `src/qr_detector.py` and `src/qr_scan.py`: QR decoding and destination analysis.
- `src/model_training.py`: validation, model selection, held-out metrics, and saved uploaded model.
- `src/ai_explainer.py`: optional GPT-6 explanations through the OpenAI Responses API.
