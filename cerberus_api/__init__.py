import logging

from flask import Flask, request
from flask_cors import CORS

from .config import Config
from .routes import api_bp


def create_app() -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config)

    _configure_logging(app)
    CORS(app, resources={r"/api/*": {"origins": "*"}})
    app.register_blueprint(api_bp)

    @app.before_request
    def log_incoming_request() -> None:
        app.logger.info(
            "Incoming request method=%s path=%s remote=%s",
            request.method,
            request.path,
            request.remote_addr,
        )

    return app


def _configure_logging(app: Flask) -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )
    app.logger.setLevel(logging.INFO)
