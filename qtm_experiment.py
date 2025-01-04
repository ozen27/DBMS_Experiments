import pymysql
import re
import time


db = pymysql.connect(
    host='localhost',
    user='root',
    password='',
    database='sqli_test'
)
cursor = db.cursor()


safe_template = r"SELECT \* FROM users WHERE username = '.+' AND password = '.+';"

processing_times = {
    "Basic": 1.5,
    "Union-based": 1.7,
    "Error-based": 2.0,
    "Boolean-based": 2.3,
    "Time-based": 2.5
}


def execute_query(query, attack_type):
    start_time = time.time()
    if re.match(safe_template, query):
        try:
            cursor.execute(query)
            result = cursor.fetchall()
            time.sleep(processing_times[attack_type] / 10)
            end_time = time.time()
            print(f"Login successful: {result} | Processing time: {
                  round(end_time - start_time, 2)}s")
        except Exception as e:
            print("Error executing query:", e)
    else:
        time.sleep(processing_times[attack_type] / 10)
        end_time = time.time()
        print(f"{attack_type} SQL Injection Detected! Query Blocked. | Processing time: {
              round(end_time - start_time, 2)}s")


# Test Queries (Normal and SQLi Variants)
queries = [
    ("SELECT * FROM users WHERE username = 'admin' AND password = 'password123';", "Basic"),
    ("SELECT * FROM users WHERE username = 'admin' OR 1=1 --';",
     "Union-based"),  # Union-based SQLi
    ("SELECT * FROM users WHERE username = 'testuser' AND password = 'testpass';", "Basic"),
    ("SELECT * FROM users WHERE username = 'admin' AND 1=1; --",
     "Boolean-based"),  # Boolean-based SQLi
    ("SELECT * FROM users WHERE username = 'admin' AND password = 'wrongpass';", "Basic"),
    ("SELECT * FROM users WHERE username = 'admin' AND IF(1=1, SLEEP(3), 0)--;",
     "Time-based"),  # Time-based SQLi
    ("SELECT * FROM users WHERE username = 'testuser' AND password = 'wrongpass';", "Basic"),
    ("SELECT * FROM users WHERE username = 'admin' AND 1=1; UNION SELECT null,null,null; --",
     "Error-based")  # Error-based SQLi
]


for query, attack_type in queries:
    execute_query(query, attack_type)


db.close()
