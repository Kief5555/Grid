# PrintedWaste Grid Service

A high-performance Node.js file hosting service with chunked uploads, Cloudflare compatibility, and advanced security features.

## Features

- **Chunked Uploads**: Automatic chunking for files over 100MB with progress tracking
- **Cloudflare Compatible**: Optimized headers and configuration for Cloudflare
- **Rate Limiting**: Built-in rate limiting and DDoS protection
- **Security**: Helmet.js security headers, input validation, and authentication
- **Performance**: Compression, caching, and optimized file handling
- **Database**: Simple JSON-based storage for easy deployment
- **File Types**: Support for images, videos, documents, and archives

## Quick Start

### Prerequisites

- Node.js 18.0.0 or higher
- npm or yarn

### Installation

1. Clone the repository:

```bash
git clone <repository-url>
cd Grid
```

2. Install dependencies:

```bash
npm install
```

3. Create environment file:

```bash
cp env.example .env
```

4. Configure environment variables:

```env
JWT=your-secret-jwt-key
RKEY=your-registration-key
PORT=3020
ALLOWED_ORIGINS=https://yourdomain.com,https://www.yourdomain.com
```

5. Start the server:

```bash
npm start
```

For development:

```bash
npm run dev
```

### Production Deployment with PM2

1. Install PM2 globally:

```bash
npm install -g pm2
```

2. Start the service:

```bash
pm2 start ecosystem.config.js
pm2 save
pm2 startup
```

3. Monitor the service:

```bash
pm2 monit
pm2 logs
```

## API Documentation

### Authentication

All API endpoints require authentication via JWT token in the Authorization header:

```
Authorization: Bearer <your-jwt-token>
```

### File Upload

#### Single Upload (Files under 100MB)

```javascript
const formData = new FormData();
formData.append('file', fileInput.files[0]);

const response = await fetch('/api/file/upload', {
    method: 'POST',
    headers: {
        'Authorization': 'Bearer ' + token,
        'X-Private': 'false',
        'X-Access-Key': 'true'
    },
    body: formData
});
```

#### Chunked Upload (Files over 100MB)

```javascript
// Initialize upload session
const initResponse = await fetch('/api/file/upload/init', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + token
    },
    body: JSON.stringify({
        filename: 'large-file.zip',
        size: 150000000, // 150MB
        chunkSize: 5242880 // 5MB chunks (optional)
    })
});

const { sessionID, totalChunks, chunkSize } = await initResponse.json();

// Upload chunks
for (let i = 0; i < totalChunks; i++) {
    const start = i * chunkSize;
    const end = Math.min(start + chunkSize, file.size);
    const chunk = file.slice(start, end);
    
    const formData = new FormData();
    formData.append('chunk', chunk);
    
    await fetch(`/api/file/upload/chunk/${sessionID}`, {
        method: 'POST',
        headers: {
            'Authorization': 'Bearer ' + token,
            'X-Chunk-Index': i.toString(),
            'X-Total-Chunks': totalChunks.toString(),
            'X-Private': 'false',
            'X-Access-Key': 'true'
        },
        body: formData
    });
}
```

### Using the Client Library

```html
<script src="/public/upload-client.js"></script>
<script>
const uploadClient = new GridUploadClient('https://your-domain.com');

// Upload with progress tracking
uploadClient.uploadFile(fileInput.files[0], {
    private: false,
    accessKey: true,
    onProgress: (percentage) => {
        console.log(`Upload progress: ${percentage}%`);
        progressBar.value = percentage;
    },
    onChunkProgress: (chunkIndex, totalChunks, chunkSize) => {
        console.log(`Chunk ${chunkIndex + 1}/${totalChunks} uploaded (${GridUploadUtils.formatFileSize(chunkSize)})`);
    }
}).then(result => {
    console.log('Upload successful:', result);
}).catch(error => {
    console.error('Upload failed:', error);
});
</script>
```

### File Management

#### Get File Info

```javascript
GET /api/file/:id
```

#### Download File

```javascript
GET /download/:id?key=access-key
```

#### View File

```javascript
GET /view/:id?key=access-key
```

#### Delete File

```javascript
DELETE /api/file/:id
Authorization: Bearer <token>
```

### User Management

#### Register User

```javascript
POST /api/user/register
Content-Type: application/json

{
    "username": "john_doe",
    "password": "secure_password",
    "registerKey": "your-registration-key"
}
```

#### Login

```javascript
POST /api/user/login
Content-Type: application/json

{
    "username": "john_doe",
    "password": "secure_password"
}
```

#### Get User Files

```javascript
GET /api/user/files
Authorization: Bearer <token>
```

#### Delete User

```javascript
DELETE /api/user/:username
Authorization: Bearer <token>
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `JWT` | JWT secret key for authentication | Required |
| `RKEY` | Registration key for new users | Required |
| `PORT` | Server port | 3020 |
| `ALLOWED_ORIGINS` | Comma-separated list of allowed CORS origins | * |

### Rate Limiting

- **General requests**: 100 requests per 15 minutes per IP
- **Uploads**: 10 uploads per hour per IP
- **Speed limiting**: 500ms delay after 50 requests per 15 minutes

### File Limits

- **Single upload**: 100MB maximum
- **Chunked upload**: 1GB maximum
- **Chunk size**: 1MB to 10MB (default: 5MB)
- **Concurrent chunks**: 3 (configurable)

## Cloudflare Configuration

### Recommended Cloudflare Settings

1. **SSL/TLS**: Full (strict)
2. **Security Level**: Medium
3. **Rate Limiting**: Enable
4. **WAF**: Enable
5. **Page Rules**: Add rules for caching static files

### Page Rules

```
URL: yourdomain.com/files/*
Settings:
- Cache Level: Cache Everything
- Edge Cache TTL: 4 hours
- Browser Cache TTL: 1 hour
```

### Worker Script (Optional)

```javascript
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

async function handleRequest(request) {
  // Add custom headers for chunked uploads
  const response = await fetch(request)
  const newResponse = new Response(response.body, response)
  
  newResponse.headers.set('X-Content-Type-Options', 'nosniff')
  newResponse.headers.set('X-Frame-Options', 'DENY')
  
  return newResponse
}
```

## Security Features

- **Helmet.js**: Security headers
- **Rate limiting**: DDoS protection
- **Input validation**: Express-validator
- **CORS**: Configurable origins
- **File type validation**: Whitelist approach
- **Authentication**: JWT tokens
- **Access keys**: Optional per-file access control

## Performance Optimizations

- **Compression**: Gzip compression for responses
- **Caching**: ETags and Cache-Control headers
- **Concurrent uploads**: Multiple chunks simultaneously
- **Database indexing**: Optimized queries
- **File streaming**: Efficient file handling
- **Memory management**: Proper cleanup of temporary files

## Database Schema

### Users Table

```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### Files Table

```sql
CREATE TABLE files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    owner TEXT NOT NULL,
    fileID TEXT UNIQUE NOT NULL,
    private BOOLEAN DEFAULT FALSE,
    accessKey TEXT,
    ext TEXT,
    size INTEGER,
    mime_type TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (owner) REFERENCES users(username)
);
```

### Upload Sessions Table

```sql
CREATE TABLE upload_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT UNIQUE NOT NULL,
    filename TEXT NOT NULL,
    owner TEXT NOT NULL,
    total_chunks INTEGER NOT NULL,
    chunk_size INTEGER NOT NULL,
    total_size INTEGER NOT NULL,
    mime_type TEXT,
    ext TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    FOREIGN KEY (owner) REFERENCES users(username)
);
```

## Error Handling

All API responses follow a consistent format:

```javascript
{
    "success": true/false,
    "data": {...},
    "errors": ["error message 1", "error message 2"]
}
```

Common HTTP status codes:

- `200`: Success
- `201`: Created (upload successful)
- `400`: Bad Request (validation errors)
- `401`: Unauthorized (authentication required)
- `404`: Not Found
- `429`: Too Many Requests (rate limited)
- `500`: Internal Server Error

## Monitoring and Logging

The service includes comprehensive logging:

- Request logging with Morgan
- Error tracking
- Upload session cleanup
- Performance metrics

### Status Endpoint

```javascript
GET /status

Response:
{
    "success": true,
    "data": {
        "status": "online",
        "totalFiles": 1234,
        "totalUsers": 56,
        "totalSize": 1073741824,
        "version": "2.0.0"
    },
    "errors": []
}
```

## Development

### Scripts

- `npm start`: Start production server
- `npm run dev`: Start development server with nodemon
- `npm test`: Run tests
- `npm run lint`: Run ESLint
- `npm run format`: Format code with Prettier

### File Structure

```
Grid/
├── index.js              # Main server file
├── package.json          # Dependencies and scripts
├── public/
│   └── upload-client.js  # Client-side upload library
├── views/
│   └── share.ejs         # Share page template
├── files/                # Uploaded files (created automatically)
├── temp/                 # Temporary chunk storage (created automatically)
└── main.db              # SQLite database (created automatically)
```

## License

ISC License - see LICENSE file for details.

## Support

For issues and questions, please create an issue in the repository or contact the maintainer.
