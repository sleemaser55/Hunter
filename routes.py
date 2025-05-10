from flask import render_template, request, jsonify, redirect, url_for, flash
import logging
from typing import Dict, List, Optional, Any

from app import app, mitre_parser, sigma_loader, splunk_query, field_mapper, splunk_connected

logger = logging.getLogger(__name__)

@app.route('/')
def index():
    """Render the home page"""
    return render_template('index.html', splunk_connected=splunk_connected)

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
    earliest = data.get('earliest', '-24h')
    latest = data.get('latest', 'now')
    count = data.get('count', 100)
    
    result = splunk_query.execute_query(
        query=query,
        earliest_time=earliest,
        latest_time=latest,
        max_count=count
    )
    
    return jsonify(result)

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

@app.route('/hunt', methods=['POST'])
def execute_hunt():
    """Execute a hunt for a MITRE technique"""
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
        rule_id = rule.get('id')
        
        # Convert to Splunk query
        splunk_query_str = sigma_loader.convert_rule_to_splunk(rule_id)
        
        if not splunk_query_str:
            results.append({
                'rule_id': rule_id,
                'rule_title': rule.get('title'),
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

@app.route('/results')
def view_results():
    """View query results page"""
    return render_template('query_results.html')

@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors"""
    return render_template('index.html', error="Page not found"), 404

@app.errorhandler(500)
def server_error(e):
    """Handle 500 errors"""
    logger.error(f"Server error: {str(e)}")
    return render_template('index.html', error="Internal server error"), 500
