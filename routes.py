from flask import render_template, request, jsonify, redirect, url_for, flash
import logging
from typing import Dict, List, Optional, Any
import config

from app import app, mitre_parser, sigma_loader, splunk_query, field_mapper, splunk_connected, apt_manager, hunt_manager
from threading import Thread
from flask import current_app
from functools import wraps

logger = logging.getLogger(__name__)

def copy_current_request_context(f):
    """Decorator to make sure that the request context is available in the thread."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        with app.request_context(request.environ):
            return f(*args, **kwargs)
    return wrapper

def check_splunk_status():
    """Helper to check Splunk status without blocking"""
    global splunk_connected
    if not splunk_connected:
        try:
            splunk_connected = splunk_query.connect()
        except:
            splunk_connected = False
    return splunk_connected

@app.route('/')
def index():
    """Render the home page"""
    splunk_status = check_splunk_status()
    return render_template('index.html', 
                          splunk_connected=splunk_status,
                          splunk_host=f"{config.SPLUNK_HOST}:{config.SPLUNK_PORT}",
                          limited_mode=not splunk_status)

@app.route('/test_visualization')
def test_visualization():
    """Test page for visualizations using sample data"""
    return render_template('test_visualization.html')

@app.route('/mitre')
def mitre_browser():
    """Render the MITRE ATT&CK browser page"""
    tactics = mitre_parser.get_tactics()
    return render_template('mitre_browser.html', tactics=tactics)

@app.route('/mitre/techniques')
def mitre_techniques():
    """Get techniques, optionally filtered by tactic"""
    tactic_id = request.args.get('tactic')
    techniques = mitre_parser.get_techniques(tactic_id)
    return jsonify(techniques)

@app.route('/api/mitre/techniques')
def api_mitre_techniques():
    """API endpoint to get MITRE techniques"""
    return mitre_techniques()

@app.route('/mitre/technique/<technique_id>')
def mitre_technique(technique_id):
    """Get details for a specific technique"""
    technique = mitre_parser.get_technique_by_id(technique_id)
    if not technique:
        return jsonify({'error': f'Technique {technique_id} not found'}), 404

    # Get associated Sigma rules
    sigma_rules = sigma_loader.get_rules_by_technique(technique_id)
    technique['sigma_rules'] = sigma_rules

    return jsonify(technique)

@app.route('/sigma')
def sigma_rules():
    """Render the Sigma rules page"""
    technique_id = request.args.get('technique')
    search_query = request.args.get('search')

    if technique_id:
        rules = sigma_loader.get_rules_by_technique(technique_id)
        technique = mitre_parser.get_technique_by_id(technique_id)
        title = f"Sigma Rules for {technique['name'] if technique else technique_id}"
    elif search_query:
        rules = sigma_loader.search_rules(search_query)
        title = f"Sigma Rules matching '{search_query}'"
    else:
        rules = sigma_loader.get_all_rules()
        title = "All Sigma Rules"

    return render_template('sigma_rules.html', rules=rules, title=title)

@app.route('/sigma/rule/<rule_id>')
def sigma_rule(rule_id):
    """Get details for a specific Sigma rule"""
    rule = sigma_loader.get_rule_by_id(rule_id)
    if not rule:
        return jsonify({'error': f'Rule {rule_id} not found'}), 404

    # Try to convert to Splunk query
    rule['splunk_query'] = sigma_loader.convert_rule_to_splunk(rule_id)

    return jsonify(rule)

@app.route('/api/sigma/rules')
def api_sigma_rules():
    """API endpoint to get all sigma rules"""
    technique_id = request.args.get('technique')
    search_query = request.args.get('search')

    if technique_id:
        rules = sigma_loader.get_rules_by_technique(technique_id)
    elif search_query:
        rules = sigma_loader.search_rules(search_query)
    else:
        rules = sigma_loader.get_all_rules()

    return jsonify(rules)

@app.route('/api/sigma/rule/<rule_id>')
def api_sigma_rule(rule_id):
    """API endpoint to get details for a specific Sigma rule"""
    return sigma_rule(rule_id)

@app.route('/api/sigma/convert/<rule_id>')
def api_convert_sigma_rule(rule_id):
    """API endpoint to convert a Sigma rule to Splunk query"""
    rule = sigma_loader.get_rule_by_id(rule_id)
    if not rule:
        return jsonify({'error': f'Rule {rule_id} not found'}), 404

    # Convert to Splunk query
    query = sigma_loader.convert_rule_to_splunk(rule_id)
    if not query:
        return jsonify({'error': f'Failed to convert rule {rule_id} to Splunk query'}), 400

    return jsonify({
        'rule_id': rule_id,
        'rule_title': rule.get('title'),
        'query': query
    })

@app.route('/api/sigma/convert', methods=['POST'])
def api_convert_sigma_yaml():
    """API endpoint to convert a Sigma rule YAML to Splunk query"""
    data = request.json

    if not data or 'yaml' not in data:
        return jsonify({'error': 'No YAML provided'}), 400

    yaml_content = data['yaml']

    try:
        # Parse YAML
        import yaml
        rule = yaml.safe_load(yaml_content)

        # Validate rule
        if not rule.get('detection'):
            return jsonify({'error': 'Invalid Sigma rule: missing detection section'}), 400

        # Convert to Splunk query
        try:
            import sigma
            from sigma.backends.splunk import SplunkBackend
            from sigma.collection import SigmaCollection
            from sigma.rule import SigmaRule

            # Create SigmaRule from dict
            sigma_rule = SigmaRule.from_dict(rule)

            # Create SigmaCollection with the rule
            sigma_collection = SigmaCollection([sigma_rule])

            # Create Splunk backend
            backend = SplunkBackend()

            # Convert to Splunk query
            query_list = backend.convert(sigma_collection)

            if not query_list:
                return jsonify({'error': 'Failed to convert rule to Splunk query'}), 400

            # Return the query
            return jsonify({
                'rule': rule,
                'query': query_list[0]
            })
        except Exception as e:
            logger.error(f"Error converting Sigma rule: {str(e)}")
            return jsonify({'error': f'Error converting rule: {str(e)}'}), 400

    except Exception as e:
        logger.error(f"Error parsing YAML: {str(e)}")
        return jsonify({'error': f'Invalid YAML: {str(e)}'}), 400

@app.route('/apt_hunt')
def apt_hunt():
    """Render the APT-based hunt page"""
    return render_template('apt_hunt.html')

@app.route('/api/hunt/apts')
def get_apts():
    """Get all APT groups"""
    return jsonify(apt_manager.get_all_apts())

@app.route('/api/hunt/apt/<apt_id>')
def get_apt_details(apt_id):
    """Get APT details with available/unavailable techniques"""
    apt = apt_manager.get_apt(apt_id)
    if not apt:
        return jsonify({'error': 'APT not found'}), 404

    # Check which techniques have Sigma rules
    available = []
    unavailable = []

    for technique_id in apt['techniques']:
        technique = mitre_parser.get_technique_by_id(technique_id)
        if not technique:
            continue

        sigma_rules = sigma_loader.get_rules_by_technique(technique_id)
        if sigma_rules:
            available.append({
                'id': technique_id,
                'name': technique['name'],
                'tactic': technique['tactics'][0] if technique['tactics'] else 'Unknown',
                'rules_count': len(sigma_rules)
            })
        else:
            unavailable.append({
                'id': technique_id,
                'name': technique['name'],
                'tactic': technique['tactics'][0] if technique['tactics'] else 'Unknown'
            })

    return jsonify({
        'name': apt['name'],
        'description': apt['description'],
        'available_techniques': available,
        'unavailable_techniques': unavailable
    })

@app.route('/api/hunt/refine', methods=['POST'])
def refine_hunt():
    """Refine hunt results based on analyst feedback"""
    data = request.json
    if not data or 'hunt_id' not in data:
        return jsonify({'error': 'Missing hunt ID'}), 400
        
    hunt = hunt_manager.get_hunt(data['hunt_id'])
    if not hunt:
        return jsonify({'error': 'Hunt not found'}), 404

    # Apply feedback filters
    if 'exclude_fields' in data:
        hunt.excluded_fields.extend(data['exclude_fields'])
    if 'exclude_values' in data:
        for field, values in data['exclude_values'].items():
            if field not in hunt.excluded_values:
                hunt.excluded_values[field] = []
            hunt.excluded_values[field].extend(values)

    # Record feedback
    hunt.feedback_history.append({
        'timestamp': datetime.datetime.now().isoformat(),
        'feedback': data
    })

    # Re-run hunt with updated filters
    hunt_manager.rerun_hunt_with_feedback(hunt.id)
    
    return jsonify({'success': True, 'hunt_id': hunt.id})

@app.route('/api/hunt/apt/start', methods=['POST'])
def start_apt_hunt():
    """Start APT-based hunt"""
    data = request.json
    if not data or 'apt_id' not in data or 'techniques' not in data:
        return jsonify({'error': 'Missing required fields'}), 400

    apt = apt_manager.get_apt(data['apt_id'])
    if not apt:
        return jsonify({'error': 'APT not found'}), 404

    # Create hunt with ordered techniques
    hunt_id = hunt_manager.start_hunt(
        hunt_type="apt",
        target_id=data['apt_id'],
        target_name=apt['name']
    )

    # Start hunt in background
    def run_hunt():
        for technique in data['techniques']:
            sigma_rules = sigma_loader.get_rules_by_technique(technique['id'])
            for rule in sigma_rules:
                query = sigma_loader.convert_rule_to_splunk(rule['id'])
                if query:
                    result = splunk_query.execute_query(query)
                    hunt_manager.update_hunt_progress(hunt_id, {
                        'query_id': rule['id'],
                        'technique_id': technique['id'],
                        'matches': result.get('matches', [])
                    })

    thread = Thread(target=run_hunt)
    thread.start()

    return jsonify({'hunt_id': hunt_id})

@app.route('/view_results')
def view_results():
    """View all hunt results"""
    return render_template('hunt_results.html',
                         current_hunts=hunt_manager.get_current_hunts(),
                         completed_hunts=hunt_manager.get_completed_hunts())

@app.route('/splunk/test', methods=['GET'])
def test_splunk():
    """Test the connection to Splunk"""
    global splunk_connected
    splunk_connected = splunk_query.connect()
    return jsonify({'success': splunk_connected})

@app.route('/splunk/query', methods=['POST'])
def execute_query():
    """Execute a Splunk query"""
    data = request.json

    if not data or 'query' not in data:
        return jsonify({'error': 'No query provided'}), 400

    query = data['query']
    use_timerange = data.get('use_timerange', True)

    # Set time range parameters if enabled
    earliest = None
    latest = None
    if use_timerange:
        earliest = data.get('earliest', '-24h')
        latest = data.get('latest', 'now')

    count = data.get('count', 100)

    result = splunk_query.execute_query(
        query=query,
        earliest_time=earliest,
        latest_time=latest,
        max_count=count
    )

    # Generate a unique ID for this result set
    import uuid
    import json
    import os
    import datetime

    result_id = str(uuid.uuid4())

    # Save results to disk for later retrieval
    # In a production app, this would be stored in a database
    try:
        # Add timestamp and query to result data
        result['timestamp'] = datetime.datetime.now().isoformat()
        result['query'] = query

        # Ensure results directory exists
        results_dir = os.path.join(app.root_path, 'data', 'results')
        os.makedirs(results_dir, exist_ok=True)

        # Save result to JSON file
        with open(os.path.join(results_dir, f"{result_id}.json"), 'w') as f:
            json.dump(result, f)

        # Add result ID to response
        result['result_id'] = result_id
    except Exception as e:
        logger.error(f"Error saving results: {str(e)}")

    return jsonify(result)

@app.route('/api/splunk/query', methods=['POST'])
def api_execute_query():
    """API endpoint to execute a Splunk query"""
    return execute_query()

@app.route('/splunk/rule/<rule_id>', methods=['POST'])
def execute_rule(rule_id):
    """Execute a Sigma rule as a Splunk query"""
    data = request.json or {}

    # Get the Splunk query for the rule
    splunk_query_str = sigma_loader.convert_rule_to_splunk(rule_id)
    if not splunk_query_str:
        return jsonify({'error': f'Failed to convert rule {rule_id} to Splunk query'}), 400

    earliest = data.get('earliest', '-24h')
    latest = data.get('latest', 'now')
    count = data.get('count', 100)

    # Execute the query
    result = splunk_query.execute_query(
        query=splunk_query_str,
        earliest_time=earliest,
        latest_time=latest,
        max_count=count
    )

    # Add rule information to the result
    rule = sigma_loader.get_rule_by_id(rule_id)
    if rule:
        result['rule'] = {
            'id': rule.get('id'),
            'title': rule.get('title'),
            'description': rule.get('description')
        }

    return jsonify(result)

@app.route('/profile_technique', methods=['GET', 'POST'])
def profile_technique():
    """Perform statistical profiling for a MITRE technique"""
    if request.method == 'GET':
        # Render the form for selecting technique and timerange
        techniques = mitre_parser.get_techniques()
        return render_template('profile_form.html', techniques=techniques)

    # Handle POST request
    data = request.json or {}
    technique_id = data.get('technique_id') or request.args.get('technique_id')

    if not technique_id:
        return jsonify({'error': 'No technique ID provided'}), 400

    earliest = data.get('earliest') or request.args.get('earliest', '-24h')
    latest = data.get('latest') or request.args.get('latest', 'now')
    index = data.get('index') or request.args.get('index', '*')

    # Check if technique exists
    technique = mitre_parser.get_technique_by_id(technique_id)
    if not technique:
        return jsonify({'error': f'Technique {technique_id} not found'}), 404

    # Import field profiler here to avoid circular imports
    from app import field_profiler

    # Perform profiling
    profiling_result = field_profiler.profile_technique(
        technique_id=technique_id,
        index=index,
        earliest_time=earliest,
        latest_time=latest
    )

    # For API requests, return JSON
    if request.headers.get('Accept') == 'application/json' or request.is_json:
        return jsonify(profiling_result)

    # For browser requests, render template
    return render_template(
        'profile_results.html',
        technique=technique,
        technique_id=technique_id,
        profiled_fields=profiling_result.get('profiled_fields', {}),
        profiling_results=profiling_result.get('profiling_results', {}),
        fast_pass_queries=profiling_result.get('fast_pass_queries', {}),
        fast_pass_results=profiling_result.get('fast_pass_results', {}),
        earliest_time=earliest,
        latest_time=latest
    )

@app.route('/hunt', methods=['GET', 'POST'])
def execute_hunt():
    """Execute a hunt for a MITRE technique"""
    # Handle GET request with parameters
    if request.method == 'GET':
        technique_id = request.args.get('technique_id')
        earliest = request.args.get('earliest', '-24h')
        latest = request.args.get('latest', 'now')
        count = int(request.args.get('count', '100'))

        if not technique_id:
            # Redirect to profile form
            return redirect(url_for('profile_technique'))

        # Create a data dictionary to reuse the POST handling logic
        data = {
            'technique_id': technique_id,
            'earliest': earliest,
            'latest': latest,
            'count': count
        }
    else:
        # For POST requests, use the JSON data
        data = request.json

        if not data or 'technique_id' not in data:
            return jsonify({'error': 'No technique ID provided'}), 400

    technique_id = data['technique_id']
    earliest = data.get('earliest', '-24h')
    latest = data.get('latest', 'now')
    count = data.get('count', 100)

    # Check if technique exists
    technique = mitre_parser.get_technique_by_id(technique_id)
    if not technique:
        return jsonify({'error': f'Technique {technique_id} not found'}), 404

    # Run pre-scan profiling if requested
    run_prescan = data.get('run_prescan', True)
    prescan_results = None

    if run_prescan:
        from app import field_profiler
        prescan_results = field_profiler.profile_technique(
            technique_id=technique_id,
            earliest_time=earliest,
            latest_time=latest
        )

    # Get Sigma rules for the technique
    sigma_rules = sigma_loader.get_rules_by_technique(technique_id)

    if not sigma_rules:
        return jsonify({
            'status': 'warning',
            'message': f'No Sigma rules found for technique {technique_id}',
            'technique': technique
        })

    # Execute each rule
    results = []

    for rule in sigma_rules:
        rule_id = rule.get('id', '')

        if not rule_id:
            continue

        # Convert to Splunk query
        splunk_query_str = sigma_loader.convert_rule_to_splunk(rule_id)

        if not splunk_query_str:
            results.append({
                'rule_id': rule_id,
                'rule_title': rule.get('title', ''),
                'status': 'error',
                'error': 'Failed to convert rule to Splunk query'
            })
            continue

        # Execute query
        result = splunk_query.execute_query(
            query=splunk_query_str,
            earliest_time=earliest,
            latest_time=latest,
            max_count=count
        )

        # Add rule information
        result['rule_id'] = rule_id
        result['rule_title'] = rule.get('title')

        results.append(result)

    # Prepare response
    response = {
        'status': 'success',
        'technique': technique,
        'rule_count': len(sigma_rules),
        'results': results,
        'earliest': earliest,
        'latest': latest
    }

    # If prescan was run, include those results
    if prescan_results:
        response['prescan_results'] = prescan_results

    return jsonify(response)

@app.route('/mappings')
def list_mappings():
    """Get field mappings"""
    category = request.args.get('category')

    if category:
        mappings = {category: field_mapper.get_fields_for_category(category)}
    else:
        mappings = field_mapper.get_all_mappings()

    return jsonify(mappings)

@app.route('/mappings/add', methods=['POST'])
def add_mapping():
    """Add or update a field mapping"""
    data = request.json

    if not data or 'category' not in data or 'field' not in data or 'mapped_field' not in data:
        return jsonify({'error': 'Invalid mapping data'}), 400

    success = field_mapper.add_mapping(
        data['category'],
        data['field'],
        data['mapped_field']
    )

    if success:
        return jsonify({'status': 'success'})
    else:
        return jsonify({'error': 'Failed to add mapping'}), 500

@app.route('/mappings/remove', methods=['POST'])
def remove_mapping():
    """Remove a field mapping"""
    data = request.json

    if not data or 'category' not in data or 'field' not in data:
        return jsonify({'error': 'Invalid mapping data'}), 400

    success = field_mapper.remove_mapping(data['category'], data['field'])

    if success:
        return jsonify({'status': 'success'})
    else:
        return jsonify({'error': 'Mapping not found'}), 404

@app.route('/mappings/manager', methods=['GET'])
def mapping_manager():
    """Render the field mapping manager page"""
    # Get all current mappings
    current_mappings = field_mapper.get_all_mappings()

    # Extract common Sigma fields from default mappings
    common_sigma_fields = field_mapper.extract_common_sigma_fields()

    # Determine if connected to Splunk for auto-detection
    global splunk_connected
    if not splunk_connected:
        splunk_connected = splunk_query.connect()

    return render_template('mapping_manager.html', 
                          current_mappings=current_mappings,
                          common_sigma_fields=common_sigma_fields,
                          splunk_connected=splunk_connected)

@app.route('/mappings/detect-auto', methods=['POST'])
def detect_auto_mappings():
    """Auto-detect field mappings based on Splunk field metadata"""
    data = request.json or {}

    # Default to all categories if none specified
    categories = data.get('categories', None)
    earliest_time = data.get('earliest_time', '-24h')
    latest_time = data.get('latest_time', 'now')

    # Extract Sigma fields to map
    common_sigma_fields = field_mapper.extract_common_sigma_fields(categories)

    # Ensure connected to Splunk
    global splunk_connected
    if not splunk_connected:
        splunk_connected = splunk_query.connect()

    if not splunk_connected:
        return jsonify({
            'status': 'error',
            'message': 'Not connected to Splunk'
        }), 500

    # Get Splunk field metadata
    splunk_fields = splunk_query.get_field_metadata(
        earliest_time=earliest_time,
        latest_time=latest_time
    )

    if not splunk_fields:
        return jsonify({
            'status': 'error',
            'message': 'Failed to retrieve Splunk field metadata'
        }), 500

    # Auto-detect mappings
    suggested_mappings = field_mapper.auto_detect_mappings(
        sigma_fields=common_sigma_fields,
        splunk_field_metadata=splunk_fields
    )

    return jsonify({
        'status': 'success',
        'suggested_mappings': suggested_mappings,
        'field_count': sum(len(fields) for category, fields in suggested_mappings.items())
    })

@app.route('/mappings/apply-suggested', methods=['POST'])
def apply_suggested_mappings():
    """Apply suggested mappings that have been approved by the user"""
    data = request.json

    if not data or 'approved_mappings' not in data:
        return jsonify({'error': 'No approved mappings provided'}), 400

    approved_mappings = data['approved_mappings']

    success = field_mapper.apply_suggested_mappings(approved_mappings)

    if success:
        return jsonify({'status': 'success'})
    else:
        return jsonify({'error': 'Failed to apply suggested mappings'}), 500

@app.route('/direct-query')
def direct_query():
    """Render the direct Splunk query page"""
    return render_template('splunk_query.html', 
                          splunk_connected=splunk_connected,
                          splunk_host=f"{config.SPLUNK_HOST}:{config.SPLUNK_PORT}")

@app.route('/sigma-execute')
def sigma_execute():
    """Render the Sigma rule execution page"""
    return render_template('sigma_execute.html', 
                          splunk_connected=splunk_connected,
                          splunk_host=f"{config.SPLUNK_HOST}:{config.SPLUNK_PORT}")

@app.route('/results')
def view_query_results():
    """View query results page"""
    result_id = request.args.get('id')
    if not result_id:
        # If no result ID is provided, redirect to query page
        return redirect(url_for('direct_query'))

    return render_template('view_results.html')

@app.route('/api/results/<result_id>')
def get_results(result_id):
    """API endpoint to get query results"""
    from app import ttp_mapper
    import os
    import json
    import traceback

    # Query results are stored in memory for now
    # In a production app, these would be stored in a database
    try:
        # Load results from saved JSON file (if exists)
        results_dir = os.path.join(app.root_path, 'data', 'results')
        os.makedirs(results_dir, exist_ok=True)

        results_file = os.path.join(results_dir, f"{result_id}.json")

        if os.path.exists(results_file):
            with open(results_file, 'r') as f:
                result_data = json.load(f)

            # Get the results list from the data
            results = result_data.get('results', [])

            # Only process TTP mappings if we have results
            if results:
                try:
                    # Map results to MITRE ATT&CK techniques
                    mappings = ttp_mapper.map_results_to_techniques(results)

                    # Create mind map data
                    mindmap = ttp_mapper.create_mindmap_data(results, mappings)
                except Exception as mapping_error:
                    logger.error(f"Error in TTP mapping: {str(mapping_error)}")
                    logger.error(traceback.format_exc())
                    mappings = {"mappings": []}
                    mindmap = {"nodes": [], "links": []}
            else:
                mappings = {"mappings": []}
                mindmap = {"nodes": [], "links": []}

            return jsonify({
                'query': result_data.get('query', ''),
                'timestamp': result_data.get('timestamp', ''),
                'results': results,
                'mappings': mappings,
                'mindmap': mindmap
            })
        else:
            return jsonify({'error': f'No results found for ID: {result_id}'}), 404

    except Exception as e:
        logger.error(f"Error retrieving results: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({'error': str(e)}), 500

@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors"""
    return render_template('index.html', error="Page not found"), 404

@app.route('/visualize/<result_id>')
def visualize_results(result_id):
    """Visualize query results"""
    # Check if result exists
    import os
    results_dir = os.path.join(app.root_path, 'data', 'results')
    result_file = os.path.join(results_dir, f"{result_id}.json")

    if not os.path.exists(result_file):
        flash(f'Results {result_id} not found', 'danger')
        return redirect(url_for('view_results'))

    return render_template('visualize_results.html', result_id=result_id)

@app.route('/api/visualize/pivot/<result_id>', methods=['GET', 'POST'])
def api_visualize_pivot(result_id):
    """Generate pivot visualization for query results"""
    # Load result data
    import os
    import json
    from app import visualizer

    results_dir = os.path.join(app.root_path, 'data', 'results')
    result_file = os.path.join(results_dir, f"{result_id}.json")

    if not os.path.exists(result_file):
        return jsonify({'status': 'error', 'message': f'Results {result_id} not found'}), 404

    try:
        with open(result_file, 'r') as f:
            result_data = json.load(f)

        # Get results
        results = result_data.get('results', [])

        if not results:
            return jsonify({
                'status': 'error', 
                'message': 'No results available for visualization'
            }), 400

        # Handle POST request (update visualization)
        if request.method == 'POST':
            data = request.json or {}
            fields = data.get('fields', [])
            layout = data.get('layout', 'physics')
        else:
            # For GET request, auto-detect important fields
            fields = []
            layout = 'physics'

        # Generate visualization data
        visualization = visualizer.generate_pivot_mindmap(results, fields)

        # Detect all available fields
        all_fields = set()
        for result in results:
            all_fields.update(result.keys())

        # Remove internal fields
        filtered_fields = [f for f in all_fields if not f.startswith('_')]

        # Select fields to include if none specified
        if not fields:
            selected_fields = visualizer._detect_important_fields(results)
        else:
            selected_fields = fields

        return jsonify({
            'status': 'success',
            'visualization': visualization,
            'available_fields': sorted(filtered_fields),
            'selected_fields': selected_fields
        })

    except Exception as e:
        logger.error(f"Error generating pivot visualization: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Error generating visualization: {str(e)}'
        }), 500

@app.route('/api/visualize/ttp/<result_id>', methods=['GET', 'POST'])
def api_visualize_ttp(result_id):
    """Generate TTP mapping visualization for query results"""
    # Load result data
    import os
    import json
    from app import visualizer, mitre_parser

    results_dir = os.path.join(app.root_path, 'data', 'results')
    result_file = os.path.join(results_dir, f"{result_id}.json")

    if not os.path.exists(result_file):
        return jsonify({'status': 'error', 'message': f'Results {result_id} not found'}), 404

    try:
        with open(result_file, 'r') as f:
            result_data = json.load(f)

        # Get results
        results = result_data.get('results', [])

        if not results:
            return jsonify({
                'status': 'error', 
                'message': 'No results available for visualization'
            }), 400

        # Handle POST request (update visualization)
        if request.method == 'POST':
            data = request.json or {}
            confidence = int(data.get('confidence', 50))
            layout = data.get('layout', 'physics')
        else:
            # For GET request, use default settings
            confidence = 50
            layout = 'physics'

        # Get techniques
        techniques = mitre_parser.get_techniques()

        # Map results to techniques
        rule_mappings = {}
        for technique in techniques:
            technique_id = technique.get('id')
            if not technique_id:
                continue

            # Check if any result fields match technique indicators
            for result in results:
                # This is a simplified mapping - in a real implementation,
                # more sophisticated matching would be used
                for field, value in result.items():
                    # Skip empty values and internal fields
                    if not value or field.startswith('_'):
                        continue

                    # Convert value to string for matching
                    str_value = str(value).lower()

                    # Check if value contains any technique keywords
                    for keyword in technique.get('keywords', []):
                        if keyword.lower() in str_value:
                            # Add to mappings
                            if technique_id not in rule_mappings:
                                                               rule_mappings[technique_id] = []

                            rule_mappings[technique_id].append(result)
                            break

        # Filter mappings by confidence threshold
        # For this example, confidence is based on the number of matches
        if confidence > 0:
            min_matches = max(1, len(results) * (confidence / 100))
            rule_mappings = {
                technique_id: matches 
                for technique_id, matches in rule_mappings.items() 
                if len(matches) >= min_matches
            }

        # Convert techniques list to a dictionary for the visualization function
        techniques_dict = {technique.get('id', f'unknown_{i}'): technique for i, technique in enumerate(techniques)}

        # Generate visualization
        visualization = visualizer.generate_ttp_mapping(results, techniques_dict, rule_mappings)

        return jsonify({
            'status': 'success',
            'visualization': visualization
        })

    except Exception as e:
        logger.error(f"Error generating TTP visualization: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Error generating visualization: {str(e)}'
        }), 500

@app.route('/api/visualize/timeline/<result_id>', methods=['GET', 'POST'])
def api_visualize_timeline(result_id):
    """Generate timeline visualization for query results"""
    # Load result data
    import os
    import json
    from app import visualizer

    results_dir = os.path.join(app.root_path, 'data', 'results')
    result_file = os.path.join(results_dir, f"{result_id}.json")

    if not os.path.exists(result_file):
        return jsonify({'status': 'error', 'message': f'Results {result_id} not found'}), 404

    try:
        with open(result_file, 'r') as f:
            result_data = json.load(f)

        # Get results
        results = result_data.get('results', [])

        if not results:
            return jsonify({
                'status': 'error', 
                'message': 'No results available for visualization'
            }), 400

        # Handle POST request (update visualization)
        if request.method == 'POST':
            data = request.json or {}
            entity_field = data.get('entity', None)
            timestamp_field = data.get('timestamp', '_time')
            visualization_mode = data.get('mode', 'grouped')
            branch_fields = data.get('branch_fields', [])
            connection_fields = data.get('connection_fields', [])
        else:
            # For GET request, use default settings
            entity_field = None
            timestamp_field = '_time'
            visualization_mode = 'grouped'
            branch_fields = []
            connection_fields = []

        # Find timestamp fields
        timestamp_fields = ['_time']
        for result in results:
            for field, value in result.items():
                if 'time' in field.lower() and field not in timestamp_fields:
                    timestamp_fields.append(field)

        # Detect all available fields for different visualizations
        all_fields = set()
        field_values = {}

        for result in results:
            for field, value in result.items():
                # Skip raw event data and null values
                if field == '_raw' or not value:
                    continue

                # Add to all fields set
                all_fields.add(field)

                # Track field values for entity detection (skip internal and timestamp fields)
                if not field.startswith('_') and field not in timestamp_fields:
                    if field not in field_values:
                        field_values[field] = set()

                    # Add string value
                    try:
                        field_values[field].add(str(value))
                    except:
                        # Skip complex values that can't be converted to strings
                        pass

        # Fields with a reasonable number of distinct values could be entities
        entity_fields = []
        for field, values in field_values.items():
            if 2 <= len(values) <= 10:  # Arbitrary threshold
                entity_fields.append(field)

        # Generate visualization based on mode
        visualization = visualizer.generate_timeline(
            results, 
            timestamp_field, 
            entity_field,
            visualization_mode,
            branch_fields,
            connection_fields
        )

        return jsonify({
            'status': 'success',
            'visualization': visualization,
            'available_timestamps': timestamp_fields,
            'selected_timestamp': timestamp_field,
            'available_entities': entity_fields,
            'selected_entity': entity_field,
            'available_fields': sorted(list(all_fields)),
            'selected_mode': visualization_mode
        })

    except Exception as e:
        logger.error(f"Error generating timeline visualization: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Error generating visualization: {str(e)}'
        }), 500

@app.route('/api/ai/analyze/<result_id>')
def api_ai_analyze(result_id):
    """Generate AI analysis for query results"""
    global splunk_connected
    from app import ai_assistant, sigma_loader, mitre_parser

    # Check if AI assistant is available
    if not ai_assistant.is_available():
        return jsonify({
            'error': 'AI analysis is not available. Please check your OpenAI API credentials.'
        }), 500

    # Load result data
    import os
    import json

    results_dir = os.path.join(app.root_path, 'data', 'results')
    result_file = os.path.join(results_dir, f"{result_id}.json")

    if not os.path.exists(result_file):
        return jsonify({'error': f'Results {result_id} not found'}), 404

    try:
        with open(result_file, 'r') as f:
            result_data = json.load(f)

        # Get results
        results = result_data.get('results', [])
        query = result_data.get('query', '')

        if not results:
            return jsonify({'error': 'No results available for analysis'}), 400

        # Try to detect which technique this might be related to
        technique_id = None
        rule = result_data.get('rule', {})

        if rule and 'id' in rule:
            # Get Sigma rule
            sigma_rule = sigma_loader.get_rule_by_id(rule['id'])
            if sigma_rule and 'tags' in sigma_rule:
                # Extract technique ID from tags
                for tag in sigma_rule['tags']:
                    if tag.startswith('attack.t'):
                        technique_id = tag.split('.')[-1]
                        break

        # If we found a technique, get its details
        technique_data = {}
        sigma_rules = []
        if technique_id:
            technique_data = mitre_parser.get_technique_by_id(technique_id)
            sigma_rules = sigma_loader.get_rules_by_technique(technique_id)

        # Get field values for context
        field_values = {}
        for result in results:
            for field, value in result.items():
                if not field.startswith('_') and value:
                    if field not in field_values:
                        field_values[field] = []

                    # Add unique values, limit to 10 per field
                    str_value = str(value)
                    if str_value not in field_values[field] and len(field_values[field]) < 10:
                        field_values[field].append(str_value)

        # If we couldn't detect a specific technique, try to enhance the query
        if technique_id and technique_data:
            analysis = ai_assistant.analyze_ttp(technique_id, technique_data, sigma_rules)
        else:
            analysis = ai_assistant.enhance_query(query, None, field_values)

        return jsonify(analysis)

    except Exception as e:
        logger.error(f"Error generating AI analysis: {str(e)}")
        return jsonify({'error': f'Error generating analysis: {str(e)}'}), 500

@app.errorhandler(500)
def server_error(e):
    """Handle 500 errors"""
    logger.error(f"Server error: {str(e)}")
    return render_template('index.html', error="Internal server error"), 500
@app.route('/hunt')
def hunt_page():
    """Render the automated hunt page"""
    return render_template('automated_hunt.html')

@app.route('/hunt/history')
def hunt_history():
    """Show hunt history"""
    hunts = hunt_manager.get_all_hunts()
    return render_template('hunt_history.html', hunts=hunts)

@app.route('/api/hunt/targets')
def hunt_targets():
    """Get available hunt targets based on type"""
    hunt_type = request.args.get('type')
    if hunt_type == 'tactic':
        return jsonify(mitre_parser.get_tactics())
    else:
        return jsonify(mitre_parser.get_techniques())

@app.route('/api/hunt/start', methods=['POST'])
def start_hunt():
    """Start a new automated hunt"""
    data = request.json
    hunt_type = data['type']
    target_id = data['target']

    # Get target name
    if hunt_type == 'tactic':
        target = mitre_parser.get_tactic_by_id(target_id)
    else:
        target = mitre_parser.get_technique_by_id(target_id)

    target_name = target['name'] if target else target_id

    # Start the hunt
    hunt_id = hunt_manager.start_hunt(hunt_type, target_id, target_name)

    # Start background task
    import threading
    @copy_current_request_context
    def run_hunt():
        # Get relevant Sigma rules
        if hunt_type == 'tactic':
            techniques = mitre_parser.get_techniques(target_id)
            rules = []
            for technique in techniques:
                rules.extend(sigma_loader.get_rules_by_technique(technique['id']))
        else:
            rules = sigma_loader.get_rules_by_technique(target_id)

        total_rules = len(rules)
        for i, rule in enumerate(rules, 1):
            # Convert rule to Splunk query
            query = sigma_loader.convert_rule_to_splunk(rule['id'])
            if not query:
                continue

            # Execute query
            result = splunk_query.execute_query(query)

            # Update hunt progress
            hunt_manager.update_hunt_progress(hunt_id, {
                'query_id': rule['id'],
                'query': query,
                'matches': result.get('results', []),
                'progress': (i / total_rules) * 100
            })

    thread = threading.Thread(target=run_hunt)
    thread.start()

    return jsonify({'hunt_id': hunt_id})