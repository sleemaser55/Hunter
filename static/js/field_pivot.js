/**
 * Field Pivot - JavaScript module for handling field-based pivoting in search results
 * This module provides functionality to:
 * 1. Extract common fields from search results
 * 2. Create pivot links for field values
 * 3. Handle pivot modal interactions
 * 4. Generate new search queries based on selected fields
 */

class FieldPivot {
    constructor() {
        this.pivotModal = null;
        this.activeField = null;
        this.activeValue = null;
        this.originalQuery = '';
    }

    /**
     * Initialize the field pivot functionality
     * @param {string} originalQuery - The original search query
     */
    init(originalQuery) {
        this.originalQuery = originalQuery || '';
        this.setupEventListeners();
    }

    /**
     * Set up event listeners for pivot interactions
     */
    setupEventListeners() {
        // Initialize Bootstrap modal
        const modalElement = document.getElementById('pivotModal');
        if (modalElement) {
            this.pivotModal = new bootstrap.Modal(modalElement);
            
            // Handle pivot execution
            const pivotExecuteBtn = document.getElementById('pivot-execute');
            if (pivotExecuteBtn) {
                pivotExecuteBtn.addEventListener('click', () => this.executePivot());
            }
            
            // Handle operator changes
            const pivotOperator = document.getElementById('pivot-operator');
            if (pivotOperator) {
                pivotOperator.addEventListener('change', () => this.updatePivotQuery());
            }
        }
    }

    /**
     * Open the pivot modal for a specific field and value
     * @param {string} field - The field name
     * @param {string} value - The field value
     */
    openPivotModal(field, value) {
        this.activeField = field;
        this.activeValue = value;
        
        // Set field and value in modal
        document.getElementById('pivot-field').value = field;
        document.getElementById('pivot-value').value = value;
        
        // Update the pivot query preview
        this.updatePivotQuery();
        
        // Show the modal
        this.pivotModal.show();
    }

    /**
     * Update the pivot query preview based on selected field, value, and operator
     */
    updatePivotQuery() {
        const field = this.activeField;
        const value = this.activeValue;
        const operator = document.getElementById('pivot-operator').value;
        
        if (!field || !value) return;
        
        let queryComponent = '';
        
        switch (operator) {
            case 'equals':
                queryComponent = `${field}="${value}"`;
                break;
            case 'contains':
                queryComponent = `${field}=*${value}*`;
                break;
            case 'startswith':
                queryComponent = `${field}=${value}*`;
                break;
            case 'endswith':
                queryComponent = `${field}=*${value}`;
                break;
            case 'notequals':
                queryComponent = `${field}!="${value}"`;
                break;
            default:
                queryComponent = `${field}="${value}"`;
        }
        
        // Get the original query without this field if it exists
        let baseQuery = this.originalQuery || '';
        
        // Remove any existing constraints for this field
        // This is a simplified version - a production implementation would use proper parsing
        const fieldPattern = new RegExp(`\\b${field}\\s*[=!]\\s*["*].*?["*]`, 'g');
        baseQuery = baseQuery.replace(fieldPattern, '').trim();
        
        // Combine with original query if it exists
        let newQuery = baseQuery;
        if (newQuery) {
            newQuery += ` ${queryComponent}`;
        } else {
            newQuery = queryComponent;
        }
        
        // Clean up any doubled spaces
        newQuery = newQuery.replace(/\s{2,}/g, ' ').trim();
        
        // Update the query preview
        document.getElementById('pivot-query').value = newQuery;
    }

    /**
     * Execute the pivot query
     */
    executePivot() {
        const query = document.getElementById('pivot-query').value;
        
        if (query) {
            // Navigate to the direct query page with the new query
            window.location.href = `/direct-query?query=${encodeURIComponent(query)}`;
        }
    }

    /**
     * Create a pivot link for a field value
     * @param {string} field - The field name
     * @param {string} value - The field value
     * @returns {HTMLElement} - The pivot link element
     */
    createPivotLink(field, value) {
        const pivotLink = document.createElement('a');
        pivotLink.className = 'pivot-link';
        pivotLink.textContent = value;
        
        // Use lambda to preserve 'this' context
        pivotLink.onclick = () => this.openPivotModal(field, value);
        
        return pivotLink;
    }

    /**
     * Get common fields from search results
     * @param {Array} results - Array of search result objects
     * @param {number} threshold - Minimum percentage of results that must contain the field
     * @returns {Array} - Array of common field names
     */
    getCommonFields(results, threshold = 0.5) {
        if (!results || !results.length) return [];
        
        const fieldCounts = {};
        const minCount = Math.max(1, Math.floor(results.length * threshold));
        
        // Count field occurrences
        results.forEach(result => {
            Object.keys(result).forEach(field => {
                fieldCounts[field] = (fieldCounts[field] || 0) + 1;
            });
        });
        
        // Filter fields by minimum count and sort by priority
        return Object.keys(fieldCounts)
            .filter(field => fieldCounts[field] >= minCount)
            .sort((a, b) => {
                // Priority fields that are commonly useful
                const priorityFields = [
                    'host', 'source', 'sourcetype', 'CommandLine', 'Image', 
                    'User', 'user', 'time', 'timestamp', 'EventID', '_time'
                ];
                
                const aPriority = priorityFields.indexOf(a);
                const bPriority = priorityFields.indexOf(b);
                
                if (aPriority !== -1 && bPriority !== -1) {
                    return aPriority - bPriority;
                }
                
                if (aPriority !== -1) return -1;
                if (bPriority !== -1) return 1;
                
                // Sort by occurrence count if not in priority list
                return fieldCounts[b] - fieldCounts[a];
            });
    }
}

// Export as global variable
window.FieldPivot = FieldPivot;