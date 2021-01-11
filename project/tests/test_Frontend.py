import pytest
import json

# test below doesn't work since Flask BC app isn't running
def test_Frontend(app, client):
    res = client.get('/')
    assert res.status_code == 200
    expected = {'hello': 'world'}
    assert expected == json.loads(res.get_data(as_text=True))
