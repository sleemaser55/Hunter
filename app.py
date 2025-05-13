import os
import logging
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, send_from_directory
from werkzeug.middleware.proxy_fix import ProxyFix
from core.hunt_manager import HuntManager
from core.apt_manager import APTManager
from core.mitre_parser import MitreAttackParser 
from core.sigma_loader import SigmaLoader
from core.field_mapper import FieldMapper
from core.splunk_query import SplunkQueryExecutor
from core.ttp_mapper import TTPMapper
from core.field_profiler import FieldProfiler
from core.visualizer import Visualizer
from core.ai_assistant import AIAssistant

import config
from core.mitre_parser import MitreAttackParser
from core.sigma_loader import SigmaLoader
from core.splunk_query import SplunkQueryExecutor
from core.field_mapper import FieldMapper
from core.ttp_mapper import TTPMapper
from core.field_profiler import FieldProfiler
from core.visualizer import Visualizer
from core.ai_assistant import AIAssistant

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Initialize the Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "default-secret-key-for-development")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Initialize core components
mitre_parser = MitreAttackParser()
sigma_loader = SigmaLoader()
field_mapper = FieldMapper()
splunk_query = SplunkQueryExecutor()
ttp_mapper = TTPMapper(mitre_parser)
hunt_manager = HuntManager()
apt_manager = APTManager()
field_profiler = FieldProfiler(sigma_loader, field_mapper, splunk_query)
visualizer = Visualizer()
ai_assistant = AIAssistant()

# Try to connect to Splunk but don't block app startup
try:
    splunk_connected = splunk_query.connect()
    if not splunk_connected:
        logger.warning("Failed to connect to Splunk on startup - continuing in limited mode")
except Exception as e:
    logger.warning(f"Error connecting to Splunk on startup: {e} - continuing in limited mode")
    splunk_connected = False

# Add a favicon route to prevent 404 errors
@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                               'favicon.ico', mimetype='image/vnd.microsoft.icon')

# Register routes
from routes import *

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
