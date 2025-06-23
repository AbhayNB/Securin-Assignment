from flask import Flask, render_template, jsonify, request,Response,render_template_string
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from apscheduler.schedulers.background import BackgroundScheduler
import requests
import logging
import yaml
import json
import os
api_key = os.getenv('api_key')
# Flask app setup
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cve.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Logging configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# CVE Model
class CVE(db.Model):
    id = db.Column(db.String(50), primary_key=True)
    source_identifier = db.Column(db.String(100))
    published = db.Column(db.DateTime)
    last_modified = db.Column(db.DateTime)
    vuln_status = db.Column(db.String(50))
    description = db.Column(db.Text)
    base_score_v2 = db.Column(db.Float)
    base_score_v3 = db.Column(db.Float)

# Fetch CVEs from API
def fetch_cves(start_index=0, results_per_page=2):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "startIndex": start_index,
        "resultsPerPage": results_per_page
    }
    headers = {
        "apiKey": api_key  # Replace with your API key
    }

    logger.info(f"Fetching CVEs: start_index={start_index}, results_per_page={results_per_page}")

    try:
        response = requests.get(url, params=params, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logger.error(f"Error fetching CVEs: {e}")
        return None

# Sync CVEs with database
def sync_cves():
    app.logger.info("sync_cves: Starting CVE sync job...")

    with app.app_context():
        start_index = 0
        while True:
            data = fetch_cves(start_index)
            if not data or 'vulnerabilities' not in data or not data['vulnerabilities']:
                logger.info("No more CVEs to process or error occurred.")
                break

            for vuln in data['vulnerabilities']:
                cve = vuln['cve']
                description = next((desc['value'] for desc in cve['descriptions'] 
                                    if desc['lang'] == 'en'), '')

                base_score_v2 = None
                base_score_v3 = None

                if 'metrics' in cve:
                    if 'cvssMetricV2' in cve['metrics']:
                        base_score_v2 = cve['metrics']['cvssMetricV2'][0]['cvssData']['baseScore']
                    if 'cvssMetricV3' in cve['metrics']:
                        base_score_v3 = cve['metrics']['cvssMetricV3'][0]['cvssData']['baseScore']

                cve_record = CVE(
                    id=cve['id'],
                    source_identifier=cve['sourceIdentifier'],
                    published=datetime.fromisoformat(cve['published'].replace('Z', '+00:00')),
                    last_modified=datetime.fromisoformat(cve['lastModified'].replace('Z', '+00:00')),
                    vuln_status=cve['vulnStatus'],
                    description=description,
                    base_score_v2=base_score_v2,
                    base_score_v3=base_score_v3
                )

                existing_cve = CVE.query.get(cve['id'])
                if existing_cve:
                    if existing_cve.last_modified < cve_record.last_modified:
                        db.session.merge(cve_record)
                else:
                    db.session.add(cve_record)

            db.session.commit()
            logger.info(f"Processed {len(data['vulnerabilities'])} CVEs.")

            start_index += 2000  # Adjust based on resultsPerPage
            app.logger.info("sync_cves: Finished CVE sync job.")

# Scheduler setup
scheduler = BackgroundScheduler()
scheduler.add_job(func=sync_cves, trigger="interval", minutes=45)
scheduler.start()

# Flask routes---------------
@app.route('/cves/list')
def index():
    return render_template('index.html')
@app.route('/cves/<cveid>')
def details(cveid):
    return render_template('details.html', cvename=cveid)

@app.route('/api/cves')
def get_cves():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    sort_by = request.args.get('sort_by', 'published')
    order = request.args.get('order', 'desc')

    query = CVE.query
    if order == 'desc':
        query = query.order_by(getattr(CVE, sort_by).desc())
    else:
        query = query.order_by(getattr(CVE, sort_by).asc())

    pagination = query.paginate(page=page, per_page=per_page)

    return jsonify({
        'total': pagination.total,
        'pages': pagination.pages,
        'current_page': page,
        'cves': [
            {
                'id': cve.id,
                'published': cve.published.isoformat(),
                'last_modified': cve.last_modified.isoformat(),
                'vuln_status': cve.vuln_status,
                'base_score_v2': cve.base_score_v2,
                'base_score_v3': cve.base_score_v3
            } for cve in pagination.items
        ]
    })

@app.route('/api/cves/<cve_id>')
def get_cve(cve_id):
    cve = CVE.query.get_or_404(cve_id)
    return jsonify({
        'id': cve.id,
        'source_identifier': cve.source_identifier,
        'published': cve.published.isoformat(),
        'last_modified': cve.last_modified.isoformat(),
        'vuln_status': cve.vuln_status,
        'description': cve.description,
        'base_score_v2': cve.base_score_v2,
        'base_score_v3': cve.base_score_v3,
        'severity': 'LOW',
        'score': 7.2,
        'vector_string': 'AV:L/AC:L/Au:N/C:C/I:C/A:C',
        'access_vector': 'LOCAL',
        'access_complexity': 'LOW',
        'authentication': 'NONE',
        'confidentiality_impact': 'COMPLETE',
        'integrity_impact': 'COMPLETE',
        'availability_impact': 'COMPLETE',
        'exploitability_score': 3.9,
        'impact_score': 10,
        'cpe_criteria': [
            'cpe:2.3:o:sun:solaris:*:*:x86:*:*:*:*',
            'cpe:2.3:o:sun:solaris:*:*:x86:*:*:*:*',
            'cpe:2.3:o:sun:solaris:*:*:x86:*:*:*:*'
        ],
        'cpe_match_criteria_id': [
            'FEECOC5A-4A6E-403C-B929-D1EC8BOFE2A8',
            'FEECOC5A-4A6E-403C-B929-D1EC8BOFE2A8',
            'FEECOC5A-4A6E-403C-B929-D1EC8BOFE2A8'
        ],
        'cpe_vulnerable': [
            True,
            True,
            True
        ]
    })
@app.route('/api/cves/year/<int:year>')
def get_cves_by_year(year):
    start_date = datetime(year, 1, 1)
    end_date = datetime(year + 1, 1, 1)
    cves = CVE.query.filter(CVE.published >= start_date, CVE.published < end_date).all()
    return jsonify([
        {
            'id': cve.id,
            'published': cve.published.isoformat(),
            'base_score_v2': cve.base_score_v2,
            'base_score_v3': cve.base_score_v3
        } for cve in cves
    ])
    
# Api doc-------

# Load OpenAPI YAML specification
def load_openapi_spec():
    with open("api.yaml", "r") as file:
        return yaml.safe_load(file)

# Route to serve the OpenAPI spec in JSON format
@app.route("/openapi.json")
def openapi_json():
    spec = load_openapi_spec()
    return jsonify(spec)

# Route to serve the OpenAPI spec in YAML format
@app.route("/openapi.yaml")
def openapi_yaml():
    spec = load_openapi_spec()
    yaml_content = yaml.dump(spec, default_flow_style=False)
    return Response(yaml_content, mimetype="application/x-yaml")

# Route to visualize the OpenAPI spec using Swagger UI
@app.route("/docs")
def swagger_ui():
    swagger_template = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>API Documentation</title>
        <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist/swagger-ui.css">
    </head>
    <body>
        <div id="swagger-ui"></div>
        <script src="https://unpkg.com/swagger-ui-dist/swagger-ui-bundle.js"></script>
        <script>
            const ui = SwaggerUIBundle({
                url: "/openapi.json", // Change this to "/openapi.yaml" if needed
                dom_id: '#swagger-ui',
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIBundle.SwaggerUIStandalonePreset
                ],
                layout: "BaseLayout",
            });
        </script>
    </body>
    </html>
    """
    return render_template_string(swagger_template)
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=5000)

