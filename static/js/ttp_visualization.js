/**
 * TTP Visualization - JavaScript module for visualizing Tactics, Techniques, and Procedures
 * This module provides functionality to:
 * 1. Render TTP mappings from search results
 * 2. Display mappings with confidence scores
 * 3. Link to MITRE ATT&CK framework
 * 4. Filter and sort mappings
 */

class TTPVisualization {
    constructor(containerId) {
        this.containerId = containerId;
        this.container = document.getElementById(containerId);
        this.mappings = [];
        this.results = [];
    }

    /**
     * Initialize the TTP visualization
     * @param {Object} mappings - TTP mapping data
     * @param {Array} results - Search results array
     */
    init(mappings, results) {
        if (!this.container) {
            console.error(`Container with ID "${this.containerId}" not found`);
            return;
        }

        this.mappings = mappings.mappings || [];
        this.results = results || [];

        this.render();
    }

    /**
     * Render the TTP visualization
     */
    render() {
        if (!this.mappings || !this.mappings.length) {
            this.container.innerHTML = '<div class="no-results">No TTP mappings found</div>';
            return;
        }

        // Create the main container
        let html = `
            <div class="mb-3">
                <div class="btn-group" role="group" aria-label="TTP visualization options">
                    <button type="button" class="btn btn-secondary active" id="ttp-table-view">Table View</button>
                    <button type="button" class="btn btn-secondary" id="ttp-matrix-view">Matrix View</button>
                </div>
                <div class="form-check form-check-inline ms-3">
                    <input class="form-check-input" type="checkbox" id="show-low-confidence" checked>
                    <label class="form-check-label" for="show-low-confidence">
                        Show Low Confidence Matches
                    </label>
                </div>
            </div>
            <div id="ttp-table-container">
                <div class="table-responsive">
                    <table class="results-table mt-3">
                        <thead>
                            <tr>
                                <th>Result #</th>
                                <th>MITRE Technique</th>
                                <th>Confidence</th>
                                <th>Tactics</th>
                            </tr>
                        </thead>
                        <tbody id="ttp-table-body">
                        </tbody>
                    </table>
                </div>
            </div>
            <div id="ttp-matrix-container" class="d-none">
                <div class="alert alert-info">
                    Matrix view shows techniques mapped across the MITRE ATT&CK tactics.
                </div>
                <div id="ttp-matrix" class="d-flex flex-wrap gap-3 mt-3">
                </div>
            </div>
        `;

        this.container.innerHTML = html;

        // Add event listeners
        document.getElementById('ttp-table-view').addEventListener('click', () => this.switchView('table'));
        document.getElementById('ttp-matrix-view').addEventListener('click', () => this.switchView('matrix'));
        document.getElementById('show-low-confidence').addEventListener('change', () => this.updateConfidenceFilter());

        // Fill the table
        this.renderTableView();
        this.renderMatrixView();
    }

    /**
     * Render the table view of TTP mappings
     */
    renderTableView() {
        const tableBody = document.getElementById('ttp-table-body');
        if (!tableBody) return;

        tableBody.innerHTML = '';

        this.mappings.forEach((mapping) => {
            const resultIndex = mapping.result_index;
            const resultData = this.results[resultIndex] || {};
            
            if (mapping.matches && mapping.matches.length) {
                mapping.matches.forEach((match) => {
                    const confidence = match.similarity_score;
                    let confidenceClass = 'low-match';
                    
                    if (confidence >= 0.7) confidenceClass = 'high-match';
                    else if (confidence >= 0.4) confidenceClass = 'medium-match';
                    
                    const row = document.createElement('tr');
                    row.dataset.confidence = confidence;
                    row.className = confidenceClass;
                    
                    row.innerHTML = `
                        <td>${resultIndex + 1}</td>
                        <td>
                            <a href="https://attack.mitre.org/techniques/${match.technique_id.replace('T', '')}" target="_blank">
                                ${match.technique_id}: ${match.technique_name}
                            </a>
                        </td>
                        <td><span class="ttp-badge ${confidenceClass}">${Math.round(confidence * 100)}%</span></td>
                        <td>${match.tactics.join(', ')}</td>
                    `;
                    
                    tableBody.appendChild(row);
                });
            } else {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${resultIndex + 1}</td>
                    <td colspan="3">No matches found</td>
                `;
                tableBody.appendChild(row);
            }
        });
    }

    /**
     * Render the matrix view of TTP mappings
     */
    renderMatrixView() {
        const matrixContainer = document.getElementById('ttp-matrix');
        if (!matrixContainer) return;

        // Define MITRE ATT&CK tactics in their standard order
        const tactics = [
            'initial-access',
            'execution',
            'persistence',
            'privilege-escalation',
            'defense-evasion',
            'credential-access',
            'discovery',
            'lateral-movement',
            'collection',
            'command-and-control',
            'exfiltration',
            'impact'
        ];

        const tacticNames = {
            'initial-access': 'Initial Access',
            'execution': 'Execution',
            'persistence': 'Persistence',
            'privilege-escalation': 'Privilege Escalation',
            'defense-evasion': 'Defense Evasion',
            'credential-access': 'Credential Access',
            'discovery': 'Discovery',
            'lateral-movement': 'Lateral Movement',
            'collection': 'Collection',
            'command-and-control': 'Command and Control',
            'exfiltration': 'Exfiltration',
            'impact': 'Impact'
        };

        // Group techniques by tactic
        const techniquesByTactic = {};
        tactics.forEach(tactic => {
            techniquesByTactic[tactic] = [];
        });

        // Collect all techniques from mappings
        this.mappings.forEach(mapping => {
            if (mapping.matches) {
                mapping.matches.forEach(match => {
                    match.tactics.forEach(tactic => {
                        // Convert tactic name to ID (slug)
                        const tacticId = tactic.toLowerCase().replace(/\s+/g, '-');
                        
                        if (tactics.includes(tacticId)) {
                            // Check if technique is already added
                            const existingTechnique = techniquesByTactic[tacticId].find(
                                t => t.technique_id === match.technique_id
                            );
                            
                            if (existingTechnique) {
                                // Update score if higher
                                if (match.similarity_score > existingTechnique.similarity_score) {
                                    existingTechnique.similarity_score = match.similarity_score;
                                    existingTechnique.resultIndices.push(mapping.result_index);
                                }
                            } else {
                                techniquesByTactic[tacticId].push({
                                    technique_id: match.technique_id,
                                    technique_name: match.technique_name,
                                    similarity_score: match.similarity_score,
                                    resultIndices: [mapping.result_index]
                                });
                            }
                        }
                    });
                });
            }
        });

        // Render tactics and techniques
        matrixContainer.innerHTML = '';
        
        tactics.forEach(tactic => {
            const techniques = techniquesByTactic[tactic];
            
            // Create tactic column
            const tacticCol = document.createElement('div');
            tacticCol.className = 'tactic-column';
            tacticCol.style.width = '200px';
            
            // Add tactic header
            const tacticHeader = document.createElement('div');
            tacticHeader.className = 'tactic-header p-2 mb-2 bg-secondary text-white text-center';
            tacticHeader.textContent = tacticNames[tactic] || tactic;
            tacticCol.appendChild(tacticHeader);
            
            // Add techniques
            if (techniques.length > 0) {
                techniques.forEach(technique => {
                    const confidenceScore = technique.similarity_score;
                    let confidenceClass = 'low-match';
                    
                    if (confidenceScore >= 0.7) confidenceClass = 'high-match';
                    else if (confidenceScore >= 0.4) confidenceClass = 'medium-match';
                    
                    const techniqueEl = document.createElement('div');
                    techniqueEl.className = `technique-cell mb-2 p-1 border ${confidenceClass}`;
                    techniqueEl.dataset.confidence = confidenceScore;
                    
                    techniqueEl.innerHTML = `
                        <div class="technique-id"><small>${technique.technique_id}</small></div>
                        <div class="technique-name">
                            <a href="https://attack.mitre.org/techniques/${technique.technique_id.replace('T', '')}" target="_blank">
                                ${technique.technique_name}
                            </a>
                        </div>
                        <div class="confidence-label">
                            <span class="ttp-badge ${confidenceClass}">${Math.round(confidenceScore * 100)}%</span>
                        </div>
                    `;
                    
                    tacticCol.appendChild(techniqueEl);
                });
            } else {
                // Empty tactic placeholder
                const emptyTactic = document.createElement('div');
                emptyTactic.className = 'p-2 text-muted text-center';
                emptyTactic.textContent = 'No techniques';
                tacticCol.appendChild(emptyTactic);
            }
            
            matrixContainer.appendChild(tacticCol);
        });
    }

    /**
     * Switch between table and matrix views
     * @param {string} view - View type ('table' or 'matrix')
     */
    switchView(view) {
        const tableBtn = document.getElementById('ttp-table-view');
        const matrixBtn = document.getElementById('ttp-matrix-view');
        const tableContainer = document.getElementById('ttp-table-container');
        const matrixContainer = document.getElementById('ttp-matrix-container');

        if (view === 'table') {
            tableBtn.classList.add('active');
            matrixBtn.classList.remove('active');
            tableContainer.classList.remove('d-none');
            matrixContainer.classList.add('d-none');
        } else {
            tableBtn.classList.remove('active');
            matrixBtn.classList.add('active');
            tableContainer.classList.add('d-none');
            matrixContainer.classList.remove('d-none');
        }
    }

    /**
     * Update the display based on confidence filter
     */
    updateConfidenceFilter() {
        const showLowConfidence = document.getElementById('show-low-confidence').checked;
        
        // Update table view
        const tableRows = document.querySelectorAll('#ttp-table-body tr');
        tableRows.forEach(row => {
            const confidence = parseFloat(row.dataset.confidence || '0');
            if (!showLowConfidence && confidence < 0.4) {
                row.style.display = 'none';
            } else {
                row.style.display = '';
            }
        });
        
        // Update matrix view
        const techniqueCells = document.querySelectorAll('.technique-cell');
        techniqueCells.forEach(cell => {
            const confidence = parseFloat(cell.dataset.confidence || '0');
            if (!showLowConfidence && confidence < 0.4) {
                cell.style.display = 'none';
            } else {
                cell.style.display = '';
            }
        });
    }
}

// Export as global variable
window.TTPVisualization = TTPVisualization;