const express = require('express');
const cors = require('cors');
const axios = require('axios');
const cheerio = require('cheerio');
const https = require('https');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
require('dotenv').config();


// Create HTTPS agent to ignore SSL certificate errors
const agent = new https.Agent({ rejectUnauthorized: false });

// 'http://results.jntuh.ac.in', 'http://202.63.105.184/results'
// ResultScraper Class
class ResultScraper {
    constructor(rollNumber, url = "http://results.jntuh.ac.in/resultAction") {
        this.url = url;
        this.rollNumber = rollNumber;
        this.results = { details: {}, results: [] };
        this.examCodeResults = [];
        this.failedExamCodes = [];
        this.examCodes = this.loadExamCodes();
        this.gradesToGPA = {
            "O": 10, "A+": 9, "A": 8, "B+": 7, "B": 6,
            "C": 5, "F": 0, "Ab": 0, "-": 0
        };
        this.payloads = this.loadPayloads();
    }

    loadExamCodes() {
        return {
            "btech": {
              "R18": {
                "1-1": ["1323", "1358", "1404", "1430", "1467", "1504", "1572", "1615","1658","1700", "1732", "1764", "1804", ],
                "1-2": ["1356", "1363","1381", "1435", "1448", "1481","1503", "1570", "1620", "1622", "1656", "1705", "1730","1769",  "1801", ],
                "2-1": ["1391", "1425", "1449", "1496", "1560", "1610", "1628", "1667", "1671", "1707", "1728", "1772", "1819", "1834", ],
                "2-2": [ "1437", "1447", "1476", "1501", "1565", "1605", "1627", "1663", "1711", "1715", "1725", "1776", "1814", "1838",],
                "3-1": [ "1454", "1491", "1550", "1590", "1626", "1639", "1645", "1655", "1686", "1697", "1722", "1784", "1789", "1828", "1832", "1842", "1846", ],
                "3-2": [ "1502", "1555", "1595", "1625", "1638", "1649", "1654", "1682", "1690", "1696", "1719", "1780", "1788", "1823", "1827", "1847", "1850", ],
                "4-1": ["1545", "1585", "1624", "1640", "1644", "1653", "1678", "1695", "1717", "1758", "1762", "1795",],
                "4-2": [ "1580", "1600", "1623", "1672", "1673", "1677", "1691", "1698", "1716", "1790", "1794", "1808", "1812", ],
              },
              "R22": {
                "1-1": ["1662", "1699", "1763", "1803"],
                "1-2": ["1704", "1768", "1800"],
                "2-1": ["1771", "1818", "1833"],
                "2-2": ["1813", "1837",],
                "3-1": [ "1841","1845",],
              },
            },
            "bpharmacy": {
                "R17": {
                    "1-1": [ "519", "537", "577", "616", "643", "683", "722", "781", "824", "832", "855", "893", "936", "973", ],
                    "1-2": [ "517", "549", "575", "591", "648", "662", "698", "727", "779", "829", "831", "853", "890", "933", "970",],
                    "2-1": [ "532", "570", "638", "673", "717", "769", "819", "849", "860", "886", "945", "983",],
                    "2-2": [ "558", "611", "650", "661", "693", "711", "774", "814", "845", "882", "897", "940", "978", ],
                    "3-1": [ "597", "633", "668", "712", "759", "799", "837", "873", "928", "965",],
                    "3-2": [ "655", "660", "688", "710", "764", "804", "841", "869", "877", "924", "961", ],
                    "4-1": [ "663", "705", "754", "794", "832", "836", "865", "920", "953", ],
                    "4-2": ["678", "700", "789", "809", "861", "878", "949", "957"],
                },
                "R22": {
                    "1-1": ["859", "892", "935", "972"],
                    "1-2": ["898", "932", "969"],
                    "2-1": ["944", "982"],
                    "2-2": ["977"],
                },
            },
            "mtech": {
                "R19": {
                    "1-1": [ "319", "332", "347", "356", "371", "382", "388", "395", "414", "422",  ],
                    "1-2": [ "328", "336", "344", "353", "368", "379", "387", "393", "412", "420",],
                    "2-1": ["337", "350", "365", "376", "386", "391", "410", "418"],
                    "2-2": ["340", "374", "385", "390", "416"],
                },
                "R22": {
                    "1-1": ["389", "394", "413", "421"],
                    "1-2": ["392", "411", "419"],
                    "2-1": ["409", "417"],
                    "2-2": ["415"],
                },
            },
            "mpharmacy": {
                "R19": {
                    "1-1": [ "161", "177", "185", "198", "209", "215", "222", "240", "248",],
                    "1-2": [ "157", "165", "174", "182", "195", "206", "214", "220", "238", "246", ],
                    "2-1": ["166", "180", "194", "204", "213", "218", "236", "244"],
                    "2-2": ["169", "203", "212", "217", "242"],
                },
                "R22": {
                    "1-1": ["216", "221", "239", "247"],
                    "1-2": ["219", "237", "245"],
                    "2-1": ["235", "243"],
                    "2-2": ["241"],
                },
            },
            "mba": {
                "R19": {
                    "1-1": [ "297", "316", "323", "350", "362", "368", "374", "405", "413",  ],
                    "1-2": [ "122", "293", "302", "313", "320", "347", "359", "367", "372", "403", "411",],
                    "2-1": ["303", "310", "344", "356", "366", "376", "401", "409"],
                    "2-2": ["120", "307", "341", "353", "365", "375", "399", "407"],
                },
                "R22": {
                    "1-1": ["369", "373", "404", "412"],
                    "1-2": ["371", "402", "410"],
                    "2-1": ["400", "408"],
                    "2-2": ["406"],
                },
            },
        }
    };

    loadPayloads() {
        return {
            "btech": [
                "&degree=btech&etype=r17&result=null&grad=null&type=intgrade&htno=",
                "&degree=btech&etype=r17&result=gradercrv&grad=null&type=rcrvintgrade&htno=",
            ],
            "bpharmacy": [
                "&degree=bpharmacy&etype=r17&grad=null&result=null&type=intgrade&htno=",
                "&degree=bpharmacy&etype=r17&grad=null&result=gradercrv&type=rcrvintgrade&htno=",
            ],
            "mba": [
                "&degree=mba&grad=pg&etype=null&result=grade17&type=intgrade&htno=",
                "&degree=mba&grad=pg&etype=r16&result=gradercrv&type=rcrvintgrade&htno=",
            ],
            "mpharmacy": [
                "&degree=mpharmacy&etype=r17&grad=pg&result=null&type=intgrade&htno=",
                "&degree=mpharmacy&etype=r17&grad=pg&result=gradercrv&type=rcrvintgrade&htno=",
            ],
            "mtech": [
                "&degree=mtech&grad=pg&etype=null&result=grade17&type=intgrade&htno=",
                "&degree=mtech&grad=pg&etype=r16&result=gradercrv&type=rcrvintgrade&htno=",
            ],
        };
    }

    async fetchResult(examCode, payload) {
        const payloadData = `?&examCode=${examCode}${payload}${this.rollNumber}`;
        try {
            const response = await axios.get(this.url + payloadData, {
                httpsAgent: agent,
                timeout: 5000
            });
            return response.data;
        } catch (error) {
            console.error(`Error fetching ${examCode}:`, error.message);
            return null;
        }
    }

    scrapeResults(semesterCode, html) {
        const $ = cheerio.load(html);
        const tables = $('table');

        if (tables.length < 2) return;

        const detailsTable = tables.eq(0);
        const resultsTable = tables.eq(1);

        // Parse student details
        const detailsRows = detailsTable.find('tr');
        const htnoAndName = detailsRows.eq(0).find('td');
        const fatherNameAndCollege = detailsRows.eq(1).find('td');

        this.results.details = {
            name: htnoAndName.eq(3).text().trim(),
            rollNo: htnoAndName.eq(1).text().trim(),
            fatherName: fatherNameAndCollege.eq(1).text().trim(),
            collegeCode: fatherNameAndCollege.eq(3).text().trim()
        };

        // Parse results
        const resultRows = resultsTable.find('tr');
        const columns = resultRows.eq(0).find('b').map((i, el) => $(el).text()).get();

        const gradeIndex = columns.indexOf("GRADE");
        const subjectNameIndex = columns.indexOf("SUBJECT NAME");
        const subjectCodeIndex = columns.indexOf("SUBJECT CODE");
        const creditsIndex = columns.indexOf("CREDITS(C)");

        const subjects = [];
        let rcrv = false;

        resultRows.slice(1).each((i, row) => {
            const cols = $(row).find('td');
            if (cols.length === 0) return;

            const subject = {
                subjectCode: cols.eq(subjectCodeIndex).text().trim(),
                subjectName: cols.eq(subjectNameIndex).text().trim(),
                subjectGrade: cols.eq(gradeIndex).text().trim(),
                subjectCredits: cols.eq(creditsIndex).text().trim()
            };

            // Check for marks columns
            const internalIndex = columns.indexOf("INTERNAL");
            if (internalIndex > -1) {
                subject.subjectInternal = cols.eq(internalIndex).text().trim();
                subject.subjectExternal = cols.eq(columns.indexOf("EXTERNAL")).text().trim();
                subject.subjectTotal = cols.eq(columns.indexOf("TOTAL")).text().trim();
            }

            if (cols.last().text().includes("Change in Grade")) {
                rcrv = true;
            }

            subjects.push(subject);
        });

        this.examCodeResults.push({
            examCode: semesterCode,
            subjects,
            rcrv
        });
    }

    determineDegree() {
        const degreeMap = { A: 'btech', R: 'bpharmacy', E: 'mba', D: 'mtech', S: 'mpharmacy' };
        return degreeMap[this.rollNumber[5]];
    }

    determineRegulation() {
        const gradYear = parseInt(this.rollNumber.substring(0, 2));
        if (gradYear >= 23 || (gradYear === 22 && this.rollNumber[4] !== '5')) {
            return 'R22';
        }
        return this.rollNumber[5] === 'A' ? 'R18' :
               this.rollNumber[5] === 'R' ? 'R17' : 'R19';
    }

    calculateSGPA(subjects) {
        let totalPoints = 0;
        let totalCredits = 0;

        subjects.forEach(subject => {
            const credits = parseFloat(subject.subjectCredits) || 0;
            // Skip subjects with 0 credits and failed subjects that might be replaced
            if (credits > 0 && subject.subjectGrade !== 'F' && subject.subjectGrade !== 'Ab') {
                const gradePoint = this.gradesToGPA[subject.subjectGrade] || 0;
                totalPoints += credits * gradePoint;
                totalCredits += credits;
            }
        });

        return totalCredits > 0 ? (totalPoints / totalCredits).toFixed(2) : "0.00";
    }

    processSemesterResults() {
        const semesterMap = new Map();

        // Group results by semesterCode
        this.examCodeResults.forEach(result => {
            if (!result.semesterCode) return;

            if (!semesterMap.has(result.semesterCode)) {
                semesterMap.set(result.semesterCode, []);
            }
            semesterMap.get(result.semesterCode).push(result);
        });

        // Process each semester group
        const processedSemesters = [];
        for (const [semesterCode, examResults] of semesterMap.entries()) {
            const subjectMap = new Map();
            let semesterName = semesterCode;
            let sgpa = "0.00";

            // Process exams in chronological order (assuming examCodes are ordered)
            examResults.forEach(exam => {
                exam.subjects.forEach(subject => {
                    const existing = subjectMap.get(subject.subjectCode);

                    // Replace if new grade is better or previous was failed
                    if (!existing ||
                        (this.gradesToGPA[subject.subjectGrade] > this.gradesToGPA[existing.subjectGrade]) ||
                        (existing.subjectGrade === 'F' && subject.subjectGrade !== 'F')) {
                        subjectMap.set(subject.subjectCode, subject);
                    }
                });
            });

            // Convert map back to array
            const consolidatedSubjects = Array.from(subjectMap.values());

            // Calculate SGPA
            sgpa = this.calculateSGPA(consolidatedSubjects);

            processedSemesters.push({
                semesterCode,
                subjects: consolidatedSubjects,
                sgpa
            });
        }

           // Sort semesters properly
           processedSemesters.sort((a, b) => {
            const [aYear, aSem] = a.semesterCode.split('-').map(Number);
            const [bYear, bSem] = b.semesterCode.split('-').map(Number);
            return aYear - bYear || aSem - bSem;
        });

        this.results.results = processedSemesters;
    }

    async scrapeAllResults(failedCodes = []) {
        const degree = this.determineDegree();
        if (!degree) return;

        const regulation = this.determineRegulation();
        const examCodes = this.examCodes[degree][regulation];

        if (this.rollNumber[4] === '5') {
            delete examCodes['1-1'];
            delete examCodes['1-2'];
        }

        const codesToFetch = failedCodes.length ? failedCodes :
            Object.values(examCodes).flat();

        const payloadList = this.payloads[degree];

        try {
            // Create array of promises for parallel execution
            const fetchPromises = codesToFetch.flatMap(code =>
                payloadList.map(payload =>
                    this.fetchResult(code, payload)
                        .then(html => {
                            if (html && !html.includes('Enter HallTicket Number') &&
                                html.includes('SUBJECT CODE')) {
                                this.scrapeResults(code, html);
                            }
                        })
                        .catch(error => {
                            console.error(`Failed to fetch ${code}:`, error);
                            this.failedExamCodes.push(code);
                        })
                )
            );

            // Wait for all requests to complete
            await Promise.all(fetchPromises);

            // Map semester codes and sort results
            this.examCodeResults.forEach(result => {
                for (const [semester, codes] of Object.entries(examCodes)) {
                    if (codes.includes(result.examCode)) {
                        result.semesterCode = semester;
                        break;
                    }
                }
            });

            // Sort results by semester in ascending order
                      this.examCodeResults.sort((a, b) => {
                        const getSemesterValue = (semData) => {
                            if (!semData.semesterCode) return 999;
                            const [year, sem] = semData.semesterCode.split('-').map(Number);
                            return year * 2 + sem - 1;
                        };
                        return getSemesterValue(a) - getSemesterValue(b);
                    });

            this.results.results = this.examCodeResults;
        } catch (error) {
            console.error('Scraping error:', error);
        }
    }

    async run(maxRetries = 10) {
        await this.scrapeAllResults();
        let retries = 0;

        while (this.failedExamCodes.length && retries < maxRetries) {
            retries++;
            const failed = [...new Set(this.failedExamCodes)];
            this.failedExamCodes = [];
            await this.scrapeAllResults(failed);
        }

        if (this.results.details.rollNo) {
            this.processSemesterResults();
            return this.results;
        }
        return null;
    }

}


const JWT_SECRET = process.env.JWT_SECRET;
// Middleware to check API key
const authenticateJWT = (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (!authHeader?.startsWith('Bearer ')) {
        return res.status(401).json({
            error: 'Access denied. Token required.'
        });
    }

    const token = authHeader.split(' ')[1];

    try {
        // Verify the token
        jwt.verify(token, JWT_SECRET);
        next();
    } catch (error) {
        return res.status(401).json({
            error: 'Invalid token.'
        });
    }
};

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // Limit each IP to 5 requests per windowMs
    message: {
        error: 'Too many requests from this IP, please try again later.'
    }
});

// Express Server Setup
const app = express();
const port = 3000;

app.use(cors());
app.use(express.json());
app.use(limiter);


app.get('/', (req, res) => {
    const apiDocs = {
        name: "JNTUH Results API",
        version: "1.0.0",
        description: "API for fetching JNTUH examination results",
        endpoints: {
            "/": {
                method: "GET",
                description: "API documentation and available endpoints",
                needsAuth: false
            },
            "/token": {
                method: "GET",
                description: "Get JWT authentication token",
                needsAuth: false,
                response: {
                    token: "JWT token valid for 24 hours"
                }
            },
            "/result": {
                method: "GET",
                description: "Fetch results for a roll number",
                needsAuth: true,
                parameters: {
                    roll: "Student roll number (10 characters)"
                },
                headers: {
                    Authorization: "Bearer <token>"
                },
                example: "/result?roll=20XX1A0XX0",
                response: {
                    details: {
                        name: "Student Name",
                        rollNo: "Roll Number",
                        fatherName: "Father's Name",
                        collegeCode: "College Code"
                    },
                    results: [
                        {
                            semesterCode: "1-1",
                            subjects: [
                                {
                                    subjectCode: "Subject Code",
                                    subjectName: "Subject Name",
                                    subjectGrade: "Grade",
                                    subjectCredits: "Credits"
                                }
                            ],
                            sgpa: "8.50"
                        }
                    ]
                }
            }
        },
        rateLimit: {
            window: "15 minutes",
            maxRequests: 5
        },
        supportedPrograms: [
            "B.Tech (Code: A)",
            "B.Pharmacy (Code: R)",
            "M.Tech (Code: D)",
            "M.Pharmacy (Code: S)",
            "MBA (Code: E)"
        ]
    };

    res.json(apiDocs);
});


app.get('/token', (req, res) => {
const token = jwt.sign({ access: 'results' }, JWT_SECRET, { expiresIn: '1d' });
console.log('Generated token:', token);
return res.json({ token });
});

app.get('/result', authenticateJWT, async (req, res) => {
    try {
        let rollNumber = req.query.roll;

        if (!rollNumber) {
            return res.status(400).json({
                error: 'Roll number is required as query parameter (?roll=YOUR_ROLL)'
            });
        }

        // Validation
        rollNumber = rollNumber.toUpperCase();
        if (rollNumber.length !== 10 || !/^[A-Z0-9]{10}$/.test(rollNumber)) {
            return res.status(400).json({
                error: 'Invalid roll number format. Must be 10 alphanumeric characters.'
            });
        }

        const scraper = new ResultScraper(rollNumber);
        const results = await scraper.run();

        if (!results) {
            return res.status(404).json({
                error: 'No results found for the provided roll number'
            });
        }

        res.setHeader('Content-Type', 'application/json');
        res.status(200).json(results);

    } catch (error) {
        console.error('Error in /result endpoint:', error);
        res.status(500).json({
            error: 'Internal server error',
            message: error.message
        });
    }
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
