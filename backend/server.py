from multiprocessing import Process
import os

# Function to run the XSS testing Flask app
def run_xss_app():
    os.system("python app.py")  # XSS Flask app script

# Function to run the SQL Injection testing Flask app
def run_sql_injection_app():
    os.system("python sqli.py")  # SQL Injection Flask app script

# Function to run the CSRF testing Flask app
def run_csrf_app():
    os.system("python csrf.py")  # CSRF Flask app script

# Function to run the Brute Force testing Flask app
def run_brute_force_app():
    os.system("python bruteforce.py")  # Brute Force Flask app script

# Function to run the Broken Access Control testing Flask app
def run_bac_app():
    os.system("python bac.py")  # Broken Access Control Flask app script

# Function to run the CORS testing Flask app
def run_cors_app():
    os.system("python cors.py")  # CORS Flask app script

# Function to run the SSL testing Flask app
def run_ssl_app():
    os.system("python test_ssl.py")  # SSL Flask app script

def run_ssrf_app():
    os.system("python ssrf.py")  # SSRF Flask app script

def run_security_app():
    os.system("python securityMisConfig.py")  # CORS Flask app script

if __name__ == "__main__":
    # Create processes for each Flask app
    xss_process = Process(target=run_xss_app)
    sql_injection_process = Process(target=run_sql_injection_app)
    csrf_process = Process(target=run_csrf_app)
    brute_force_process = Process(target=run_brute_force_app)
    bac_process = Process(target=run_bac_app)
    cors_process = Process(target=run_cors_app)
    ssl_process = Process(target=run_ssl_app)
    ssrf_process = Process(target=run_ssrf_app)
    security_process = Process(target=run_security_app)


    # Start all processes
    xss_process.start()
    sql_injection_process.start()
    csrf_process.start()
    brute_force_process.start()
    bac_process.start()
    cors_process.start()
    ssl_process.start()
    ssrf_process.start()
    security_process.start()

    print("All eight Flask apps are running...")

    # Wait for the processes to finish
    xss_process.join()
    sql_injection_process.join()
    csrf_process.join()
    brute_force_process.join()
    bac_process.join()
    cors_process.join()
    ssl_process.join()
    ssrf_process.join()
    security_process.join()

    print("All eight Flask apps have finished running.")
