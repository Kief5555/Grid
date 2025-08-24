# Grid Service

A high-performance Node.js file hosting service with chunked uploads and Cloudflare compatibility.

## Features

- Chunked uploads for files over 100MB
- Cloudflare compatible headers and configuration
- Rate limiting and DDoS protection
- Security headers and input validation
- Compression and caching
- Simple JSON-based storage
- Support for images, videos, documents, and archives

## Setup

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

4. Configure environment variables in `.env`:

```env
JWT=your-secret-jwt-key
RKEY=your-registration-key
PORT=3020
```

5. Start the server:

```bash
npm start
```

For development:

```bash
npm run dev
```

### Production Deployment

Install PM2 and start the service:

```bash
npm install -g pm2
pm2 start ecosystem.config.js
pm2 save
pm2 startup
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
        size: 150000000,
        chunkSize: 5242880
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

### File Management

- `GET /api/file/:id` - Get file info
- `GET /download/:id?key=access-key` - Download file
- `GET /view/:id?key=access-key` - View file
- `DELETE /api/file/:id` - Delete file

### User Management

- `POST /api/user/register` - Register user
- `POST /api/user/login` - Login
- `GET /api/user/files` - Get user files
- `DELETE /api/user/:username` - Delete user

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `JWT` | JWT secret key for authentication | Required |
| `RKEY` | Registration key for new users | Required |
| `PORT` | Server port | 3020 |

### Rate Limiting

- General requests: 100 requests per 15 minutes per IP
- Uploads: 10 uploads per hour per IP
- Speed limiting: 500ms delay after 50 requests per 15 minutes

### File Limits

- Single upload: 100MB maximum
- Chunked upload: 1GB maximum
- Chunk size: 1MB to 10MB (default: 5MB)
- Concurrent chunks: 3

## Cloudflare Configuration

### Recommended Settings

1. SSL/TLS: Full (strict)
2. Security Level: Medium
3. Rate Limiting: Enable
4. WAF: Enable

The service is configured to trust the first proxy (Cloudflare) for proper rate limiting and IP detection.

### Page Rules

```
URL: yourdomain.com/files/*
Settings:
- Cache Level: Cache Everything
- Edge Cache TTL: 4 hours
- Browser Cache TTL: 1 hour
```

## Data Storage

The service uses JSON-based storage for easy deployment:

```
data/
├── users.json      # User accounts and authentication
├── files.json      # File metadata and access control
└── sessions.json   # Active upload sessions
```

All data files are automatically created on first run.

## Error Handling

All API responses follow a consistent format:

```javascript
{
    "success": true/false,
    "data": {...},
    "errors": ["error message 1", "error message 2"]
}
```

## Monitoring

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
├── ecosystem.config.js   # PM2 configuration
├── api-docs.yaml        # OpenAPI documentation
├── env.example          # Environment template
├── public/
│   └── upload-client.js # Client-side upload library
├── views/
│   └── share.ejs        # Share page template
├── files/               # Uploaded files (auto-created)
├── temp/                # Temporary chunks (auto-created)
├── data/                # JSON database files (auto-created)
└── logs/                # PM2 logs (auto-created)
```

## License

ISC License - see LICENSE file for details.
