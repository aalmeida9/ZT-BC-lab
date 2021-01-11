from flask import Flask, request
#config: https://exploreflask.com/en/latest/configuration.html

app = Flask(__name__)

from frontend import views

# Create Flask app with "app factory"
def create_app():
    app_name = 'frontend'
    print('app_name = {}'.format(app_name))

    # app = Flask(__name__, instance_relative_config=True)
    app = Flask(__name__)

    # not sure if this needs to be put here
    from frontend import views
    return app
