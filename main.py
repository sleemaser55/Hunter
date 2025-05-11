import logging
from app import app

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Print startup message
logger.info("Starting Security Hunter application...")
logger.info("Server will be accessible at http://0.0.0.0:5000")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
