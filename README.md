# JNTUH Results API

A Node.js API that scrapes and serves JNTUH (Jawaharlal Nehru Technological University Hyderabad) examination results. This API can fetch results for B.Tech, B.Pharmacy, M.Tech, M.Pharmacy, and MBA programs.

## Features

- Fetches complete semester results for any valid roll number
- Supports multiple degree programs (B.Tech, B.Pharmacy, M.Tech, M.Pharmacy, MBA)
- Calculates SGPA for each semester
- JWT-based authentication
- Rate limiting to prevent abuse
- CORS enabled
- Error handling and validation

## Prerequisites

- Node.js (v12 or higher)
- npm (Node Package Manager)

## Installation

1. Clone the repository:
```sh
git clone https://github.com/aravindchilpa/jntuh-results-backend.git
cd jntuh-results-backend
```

2. Install dependencies:
```sh
npm install
```

3. Create a `.env` file in the backend directory:
```sh
JWT_SECRET=your-super-secret-key-here
```

## Usage

1. Start the server:
```sh
node index.js
```

2. Get an authentication token:
```sh
GET http://localhost:3000/token
```

3. Fetch results using the token:
```sh
GET http://localhost:3000/result?roll=YOURROLLNUM
Headers: Authorization: Bearer <your-token>
```

## API Endpoints

- `GET /token` - Generate a JWT token (valid for 01 day)
- `GET /result?roll=<roll_number>` - Fetch results for a specific roll number

## Dependencies

- `express` - Web framework
- `axios` - HTTP client for making requests
- `cheerio` - HTML parsing and scraping
- `cors` - Cross-Origin Resource Sharing
- `dotenv` - Environment variables management
- `jsonwebtoken` - JWT authentication
- `express-rate-limit` - Rate limiting middleware
- `bcryptjs` - Password hashing
- `https` - HTTPS module for SSL/TLS

## Rate Limiting

The API is limited to:
- 10 requests per IP address
- 15-minute window

## Response Format

```json
{
  "details": {
    "name": "Student Name",
    "rollNo": "Roll Number",
    "fatherName": "Father's Name",
    "collegeCode": "College Code"
  },
  "results": [
    {
      "semesterCode": "1-1",
      "subjects": [
        {
          "subjectCode": "Subject Code",
          "subjectName": "Subject Name",
          "subjectGrade": "Grade",
          "subjectCredits": "Credits"
        }
      ],
      "sgpa": "8.50"
    }
  ]
}
```

## Error Handling

The API returns appropriate HTTP status codes:
- 200: Successful response
- 400: Invalid roll number format
- 401: Invalid/missing token
- 404: No results found
- 429: Too many requests
- 500: Server error

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License

MIT

## Disclaimer

This project is for educational purposes only. Use it responsibly and in accordance with JNTUH's terms of service.
