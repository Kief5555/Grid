/**
 * PrintedWaste Grid Upload Client
 * Handles chunked uploads for files over 100MB with progress tracking and retry logic
 * Compatible with Cloudflare and optimized for performance
 */

class GridUploadClient {
    constructor(baseUrl = '', options = {}) {
        this.baseUrl = baseUrl.replace(/\/$/, '');
        this.options = {
            chunkSize: 5 * 1024 * 1024, // 5MB default chunks
            maxRetries: 3,
            retryDelay: 1000,
            concurrentChunks: 3,
            ...options
        };
        this.activeUploads = new Map();
    }

    /**
     * Upload a file with automatic chunking for files over 100MB
     * @param {File} file - The file to upload
     * @param {Object} options - Upload options
     * @returns {Promise<Object>} Upload result
     */
    async uploadFile(file, options = {}) {
        const uploadOptions = {
            private: false,
            accessKey: false,
            onProgress: null,
            onChunkProgress: null,
            ...options
        };

        // For files under 100MB, use single upload
        if (file.size <= 100 * 1024 * 1024) {
            return this.singleUpload(file, uploadOptions);
        }

        // For files over 100MB, use chunked upload
        return this.chunkedUpload(file, uploadOptions);
    }

    /**
     * Single file upload for files under 100MB
     */
    async singleUpload(file, options) {
        const formData = new FormData();
        formData.append('file', file);

        const headers = {
            'Authorization': this.getAuthHeader(),
            'X-Private': options.private.toString(),
            'X-Access-Key': options.accessKey.toString()
        };

        try {
            const response = await fetch(`${this.baseUrl}/api/file/upload`, {
                method: 'POST',
                headers,
                body: formData
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.errors?.[0] || 'Upload failed');
            }

            const result = await response.json();

            if (options.onProgress) {
                options.onProgress(100);
            }

            return result.data;
        } catch (error) {
            throw new Error(`Single upload failed: ${error.message}`);
        }
    }

    /**
     * Chunked upload for files over 100MB
     */
    async chunkedUpload(file, options) {
        const sessionId = crypto.randomUUID();
        const uploadId = `${sessionId}-${Date.now()}`;

        // Initialize upload session
        const initResponse = await this.initUploadSession(file, options);
        const { sessionID, totalChunks, chunkSize } = initResponse;

        // Create upload progress tracker
        const progress = {
            uploadedChunks: 0,
            totalChunks,
            totalSize: file.size,
            uploadedSize: 0,
            failedChunks: new Set(),
            retryCount: 0
        };

        // Upload chunks with concurrency control
        const chunkPromises = [];
        const semaphore = new Semaphore(this.options.concurrentChunks);

        for (let i = 0; i < totalChunks; i++) {
            const chunkPromise = semaphore.acquire().then(async () => {
                try {
                    await this.uploadChunk(file, sessionID, i, totalChunks, chunkSize, progress, options);
                } finally {
                    semaphore.release();
                }
            });
            chunkPromises.push(chunkPromise);
        }

        // Wait for all chunks to complete
        await Promise.all(chunkPromises);

        // Check if any chunks failed and retry if needed
        while (progress.failedChunks.size > 0 && progress.retryCount < this.options.maxRetries) {
            progress.retryCount++;
            console.log(`Retrying ${progress.failedChunks.size} failed chunks (attempt ${progress.retryCount})`);

            const failedChunks = Array.from(progress.failedChunks);
            progress.failedChunks.clear();

            await Promise.all(
                failedChunks.map(chunkIndex =>
                    semaphore.acquire().then(async () => {
                        try {
                            await this.uploadChunk(file, sessionID, chunkIndex, totalChunks, chunkSize, progress, options);
                        } finally {
                            semaphore.release();
                        }
                    })
                )
            );

            // Wait before retry
            if (progress.failedChunks.size > 0) {
                await this.delay(this.options.retryDelay * progress.retryCount);
            }
        }

        if (progress.failedChunks.size > 0) {
            throw new Error(`Upload failed: ${progress.failedChunks.size} chunks could not be uploaded after ${this.options.maxRetries} retries`);
        }

        // Finalize upload
        const finalResponse = await this.finalizeUpload(sessionID, options);

        if (options.onProgress) {
            options.onProgress(100);
        }

        return finalResponse;
    }

    /**
     * Initialize upload session
     */
    async initUploadSession(file, options) {
        const response = await fetch(`${this.baseUrl}/api/file/upload/init`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': this.getAuthHeader()
            },
            body: JSON.stringify({
                filename: file.name,
                size: file.size,
                chunkSize: this.options.chunkSize
            })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.errors?.[0] || 'Failed to initialize upload');
        }

        return (await response.json()).data;
    }

    /**
     * Upload a single chunk
     */
    async uploadChunk(file, sessionID, chunkIndex, totalChunks, chunkSize, progress, options) {
        const start = chunkIndex * chunkSize;
        const end = Math.min(start + chunkSize, file.size);
        const chunk = file.slice(start, end);

        const formData = new FormData();
        formData.append('chunk', chunk);

        const headers = {
            'Authorization': this.getAuthHeader(),
            'X-Chunk-Index': chunkIndex.toString(),
            'X-Total-Chunks': totalChunks.toString(),
            'X-Private': options.private.toString(),
            'X-Access-Key': options.accessKey.toString()
        };

        try {
            const response = await fetch(`${this.baseUrl}/api/file/upload/chunk/${sessionID}`, {
                method: 'POST',
                headers,
                body: formData
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.errors?.[0] || `Chunk ${chunkIndex} upload failed`);
            }

            const result = await response.json();

            // Update progress
            progress.uploadedChunks++;
            progress.uploadedSize += chunk.size;

            if (options.onChunkProgress) {
                options.onChunkProgress(chunkIndex, totalChunks, chunk.size);
            }

            if (options.onProgress) {
                const percentage = Math.round((progress.uploadedSize / progress.totalSize) * 100);
                options.onProgress(percentage);
            }

            // Check if upload is complete
            if (result.data.fileID) {
                return result.data;
            }

        } catch (error) {
            console.error(`Chunk ${chunkIndex} upload failed:`, error);
            progress.failedChunks.add(chunkIndex);
            throw error;
        }
    }

    /**
     * Finalize upload (handled automatically in chunk upload)
     */
    async finalizeUpload(sessionID, options) {
        // The finalization is handled automatically when the last chunk is uploaded
        // This method is kept for potential future use
        return { sessionID, message: 'Upload completed' };
    }

    /**
     * Get authentication header
     */
    getAuthHeader() {
        const token = localStorage.getItem('grid_token') || sessionStorage.getItem('grid_token');
        return token ? `Bearer ${token}` : '';
    }

    /**
     * Set authentication token
     */
    setAuthToken(token, persistent = true) {
        if (persistent) {
            localStorage.setItem('grid_token', token);
        } else {
            sessionStorage.setItem('grid_token', token);
        }
    }

    /**
     * Clear authentication token
     */
    clearAuthToken() {
        localStorage.removeItem('grid_token');
        sessionStorage.removeItem('grid_token');
    }

    /**
     * Utility function for delays
     */
    delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    /**
     * Cancel an active upload
     */
    cancelUpload(uploadId) {
        const upload = this.activeUploads.get(uploadId);
        if (upload) {
            upload.cancelled = true;
            this.activeUploads.delete(uploadId);
        }
    }

    /**
     * Get upload status
     */
    getUploadStatus(uploadId) {
        return this.activeUploads.get(uploadId);
    }
}

/**
 * Semaphore for controlling concurrent operations
 */
class Semaphore {
    constructor(max) {
        this.max = max;
        this.count = 0;
        this.queue = [];
    }

    async acquire() {
        if (this.count < this.max) {
            this.count++;
            return Promise.resolve();
        }

        return new Promise(resolve => {
            this.queue.push(resolve);
        });
    }

    release() {
        this.count--;
        if (this.queue.length > 0) {
            this.count++;
            const next = this.queue.shift();
            next();
        }
    }
}

/**
 * File upload utility functions
 */
class GridUploadUtils {
    /**
     * Format file size for display
     */
    static formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    /**
     * Validate file type
     */
    static isValidFileType(file) {
        const allowedTypes = [
            'image/', 'video/', 'audio/', 'text/', 'application/pdf',
            'application/zip', 'application/x-zip-compressed',
            'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'application/vnd.ms-powerpoint', 'application/vnd.openxmlformats-officedocument.presentationml.presentation'
        ];

        return allowedTypes.some(type => file.type.startsWith(type));
    }

    /**
     * Get file extension from filename
     */
    static getFileExtension(filename) {
        return filename.slice((filename.lastIndexOf('.') - 1 >>> 0) + 2);
    }

    /**
     * Generate a unique upload ID
     */
    static generateUploadId() {
        return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    }
}

// Export for different module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { GridUploadClient, GridUploadUtils };
} else if (typeof window !== 'undefined') {
    window.GridUploadClient = GridUploadClient;
    window.GridUploadUtils = GridUploadUtils;
}
