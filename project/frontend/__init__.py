from flask import Flask, request
#config: https://exploreflask.com/en/latest/configuration.html

app = Flask(__name__)

from frontend import views

#Alternative way to create app with Flask (app factory)
def create_app():
    app_name = 'frontend'
    print('app_name = {}'.format(app_name))

    # create app
    # app = Flask(__name__, instance_relative_config=True)
    app = Flask(__name__)

    # @app.route("/")
    # def hello():
    #     return 'Hello ' + app_name + '! request.url = ' + request.url

    #not sure if should be put here or above
    # from frontend import views

    # return app
    return app
