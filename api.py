#samp branch
from flask import Flask, render_template, request, jsonify
import pandas as pd
import re
from urllib.parse import urlparse
from tld import get_tld
import joblib
import csv
from flask import send_file
import io
from flask import Response

# Initialize Flask app
app = Flask(__name__)

# Load the trained model and LabelEncoder
loaded_model = joblib.load('C:/Skill/Gelecek/day_1/Task_1/Malicious.pkl')
lb_make = joblib.load('C:/Skill/Gelecek/day_1/Task_1/LabelEncoder.pkl')

# Feature extraction functions (same as you already have)

def having_ip_address(url):
    match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.' 
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' # IPv4 in hexadecimal
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)  # Ipv6
    if match:
        return 1
    else:
        return 0

def abnormal_url(url):
    hostname = urlparse(url).hostname
    hostname = str(hostname)
    match = re.search(hostname, url)
    if match:
        return 1
    else:
        return 0

def no_of_dir(url):
    urldir = urlparse(url).path
    return urldir.count('/')

def no_of_embed(url):
    urldir = urlparse(url).path
    return urldir.count('//')

def shortening_service(url):
    match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                      'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                      'x\.co', url)
    if match:
        return 1
    else:
        return 0

def suspicious_words(url):
    match = re.search('PayPal|login|signin|bank|account|update|free|lucky|service|bonus|ebayisapi|webscr',
                      url)
    if match:
        return 1
    else:
        return 0

def fd_length(url):
    urlpath= urlparse(url).path
    try:
        return len(urlpath.split('/')[1])
    except:
        return 0

def tld_length(tld):
    try:
        return len(tld)
    except:
        return -1

def digit_count(url):
    digits = 0
    for i in url:
        if i.isnumeric():
            digits = digits + 1
    return digits

def letter_count(url):
    letters = 0
    for i in url:
        if i.isalpha():
            letters = letters + 1
    return letters

def predict_url(url):
    features = pd.DataFrame({
        'use_of_ip': [having_ip_address(url)],
        'abnormal_url': [abnormal_url(url)],
        'count.': [url.count('.')],
        'count-www': [url.count('www')],
        'count@': [url.count('@')],
        'count_dir': [no_of_dir(url)],
        'count_embed_domian': [no_of_embed(url)],
        'short_url': [shortening_service(url)],
        'count-https': [url.count('https')],
        'count-http': [url.count('http')],
        'count%': [url.count('%')],
        'count?': [url.count('?')],
        'count-': [url.count('-')],
        'count=': [url.count('=')],
        'url_length': [len(url)],
        'hostname_length': [len(urlparse(url).netloc)],
        'sus_url': [suspicious_words(url)],
        'fd_length': [fd_length(url)],
        'tld_length': [tld_length(get_tld(url, fail_silently=True))],
        'count-digits': [digit_count(url)],
        'count-letters': [letter_count(url)]
    })

    # Prediction
    prediction_encoded = loaded_model.predict(features)
    # Decode the prediction to get the original class label
    prediction = lb_make.inverse_transform(prediction_encoded)

    return prediction[0]

import sqlite3

# Function to initialize the database and create the table
def init_db():
    conn = sqlite3.connect('url_predictions.db')  # Connect to the SQLite database (it creates the file if it doesn't exist)
    c = conn.cursor()  # Create a cursor object to interact with the database
    c.execute('''
        CREATE TABLE IF NOT EXISTS predictions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            prediction TEXT NOT NULL
        )
    ''')  # Create the table if it doesn't already exist
    conn.commit()  # Commit the transaction
    conn.close()  # Close the connection


# Route to display the form
@app.route('/')
def index():
    return render_template('index.html')

# Route to handle form submission
@app.route('/predict', methods=['POST'])
def predict():
    # Get URL from the form
    url = request.form.get('url')
    
    if url:
        prediction = predict_url(url)  # Get the prediction for the URL
        
        # Insert the URL and prediction into the database
        conn = sqlite3.connect('url_predictions.db')
        c = conn.cursor()
        c.execute('''
            INSERT INTO predictions (url, prediction) VALUES (?, ?)
        ''', (url, prediction))  # Insert the URL and its prediction
        conn.commit()  # Commit the transaction
        conn.close()  # Close the connection
        
        return render_template('index.html', prediction=prediction, url=url)
    else:
        return render_template('index.html', error="Please enter a URL to predict.")

@app.route('/history')
def history():
    # Fetch all records from the database
    conn = sqlite3.connect('url_predictions.db')
    c = conn.cursor()
    c.execute('SELECT * FROM predictions')  # Get all records from the predictions table
    records = c.fetchall()  # Fetch all rows as a list of tuples
    conn.close()  # Close the connection
    
    return render_template('history.html', records=records)  # Pass records to the history page


# Route to download the prediction history as CSV
@app.route('/download_history')
def download_history():
    # Fetch all records from the database
    conn = sqlite3.connect('url_predictions.db')
    c = conn.cursor()
    c.execute('SELECT * FROM predictions')  # Get all records from the predictions table
    records = c.fetchall()  # Fetch all rows as a list of tuples
    conn.close()  # Close the connection

    # Create an in-memory string buffer
    output = io.StringIO()
    
    # Create a CSV writer object that writes to the buffer
    writer = csv.writer(output)
    
    # Write the header row
    writer.writerow(["ID", "URL", "Prediction"])

    # Write the data rows
    for record in records:
        writer.writerow([record[0], record[1], record[2]])  # Writing ID, URL, and Prediction

    # Seek to the start of the StringIO buffer
    output.seek(0)

    # Return the contents of the StringIO buffer as a downloadable CSV file
    return Response(output.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=prediction_history.csv"})


# Run the Flask app
if __name__ == '__main__':
    init_db()  # Initialize the database when the app starts
    app.run(host='0.0.0.0', port=5000, debug=True)

