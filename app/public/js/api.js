import { state } from './state.js';
import { showToast } from './utils.js';

export async function initSession() {
    try {
        const res = await fetch('/api/csrf');
        if (!res.ok) throw new Error('Failed to fetch CSRF token');
        const data = await res.json();
        state.csrfToken = data.token; // It was data.token in system.routes.js
    } catch (err) {
        console.error('CSRF initiation error:', err);
    }
}

export async function secureFetch(url, options = {}) {
    if (!options.headers) {
        options.headers = {};
    }
    
    // Add CSRF token for state-changing requests
    if (options.method && !['GET', 'HEAD', 'OPTIONS'].includes(options.method.toUpperCase())) {
        options.headers['X-CSRF-Token'] = state.csrfToken;
    }
    
    if (options.body && typeof options.body === 'object') {
        options.headers['Content-Type'] = 'application/json';
        options.body = JSON.stringify(options.body);
    }

    try {
        const response = await fetch(url, options);
        
        if (response.status === 401) {
            // Session expired, redirect to login
            window.location.href = '/login';
            return null;
        }

        // --- Common Error/Success Handling ---
        if (!options.silent) {
            const clone = response.clone();
            clone.json().then(data => {
                if (!response.ok) {
                    showToast(data.error || `Error: ${response.statusText}`, 'error');
                } else if (options.method && ['POST', 'PUT', 'DELETE'].includes(options.method.toUpperCase())) {
                    if (data.message || data.successMessage) {
                        showToast(data.message || data.successMessage, 'success');
                    } else if (data.success || data.synced || data.id || data.proxy) {
                        showToast('Operation completed successfully', 'success');
                    }
                }
            }).catch(() => {
                if (!response.ok) showToast(`Error: ${response.statusText}`, 'error');
            });
        }
        
        return response;
    } catch (err) {
        if (!options.silent) showToast('Network Error: ' + err.message, 'error');
        return null;
    }
}
