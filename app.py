from website import create_app
from flask import Flask
app = create_app()

if __name__ == "__main__":
    from waitress import serve
    serve(app, host="0.0.0.0")
    app.debug = True