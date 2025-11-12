from flask import Flask, request, render_template_string
import sqlite3

app = Flask(__name__)
# simple DB
conn = sqlite3.connect(':memory:', check_same_thread=False)
conn.execute("CREATE TABLE users(id INTEGER PRIMARY KEY, name TEXT);")
conn.execute("INSERT INTO users (name) VALUES ('alice'),('bob');")
conn.commit()

@app.route("/search")
def search():
    q = request.args.get('q','')
    # vulnerable: string concat into SQL (ONLY in this lab example)
    cur = conn.execute("SELECT name FROM users WHERE name LIKE '%{}%'".format(q))
    rows = cur.fetchall()
    return render_template_string("<h1>Search Results</h1><pre>{{rows}}</pre>", rows=rows)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000)
