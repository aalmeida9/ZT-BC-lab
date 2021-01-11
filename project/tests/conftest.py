import pytest
#from webtest import TestApp

#from frontend import create_app
#from yourflaskmodule.config import test_config
from frontend import app as flask_app
#from module.settings import TestConfig


@pytest.fixture
def app():
    yield flask_app


@pytest.fixture
def client(app):
    return app.test_client()
