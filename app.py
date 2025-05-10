import os
import logging
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from werkzeug.middleware.proxy_fix import ProxyFix

import config
from core.mitre_parser import MitreAttackParser
from core.sigma_loader import SigmaLoader
from core.splunk_query import SplunkQueryExecutor
from core.field_mapper import FieldMapper

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
splunk_query = SplunkQueryExecutor()
field_mapper = FieldMapper()

# Connect to Splunk (done here so we don't have to reconnect for every request)
splunk_connected = splunk_query.connect()
if not splunk_connected:
    logger.warning("Failed to connect to Splunk on startup")

# Import routes
import routes

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
