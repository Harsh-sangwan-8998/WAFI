from flask import Flask, render_template

app = Flask(__name__)

@app.route("/")
def hello_world():
    return render_template('welcome.html')  # Ensure the file exists in 'templates/template/'

@app.route("/homepage")
def homepage():
    return "This is a home page"

if __name__ == "__main__":
    app.run(debug=True)
