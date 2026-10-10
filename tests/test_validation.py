import pytest
from h11_cga.adapters.log_adapter import LogAdapter
from h11_cga.benchmarks.validation import evaluate
from h11_cga.types import DIMENSION_NAMES


def episode(identity, malicious, value):
    nominal = {d.lower(): 1.0 for d in DIMENSION_NAMES}
    return dict(id=identity, malicious=malicious, source='synthetic regression only', calibration=[nominal]*20, samples=[{d.lower():value for d in DIMENSION_NAMES}]*3)


def test_replay_counts_both_false_positives_and_missed_incidents():
    result = evaluate([episode('tp',True,0),episode('tn',False,1),episode('fp',False,0),episode('fn',True,1)])
    assert result['counts'] == dict(tp=1,tn=1,fp=1,fn=1)
    assert result['recall'] == result['false_positive_rate'] == .5


def test_missing_dimensions_and_duplicate_episodes_rejected():
    record = episode('a',True,0)
    del record['samples'][0]['governance']
    with pytest.raises(ValueError):
        evaluate([record])
    with pytest.raises(ValueError):
        evaluate([episode('a',True,0),episode('a',False,1)])


@pytest.mark.parametrize('payload', ['[]','null','1',{'action':[]},{'status':'denied','severity':float('nan')},{'status':'denied','severity':True}])
def test_malformed_audit_input_fails_closed(payload):
    adapter = LogAdapter()
    assert adapter.ingest_json_log(payload) is None
    assert not adapter.collect().events


def test_log_overload_is_bounded_and_visible():
    adapter = LogAdapter(max_pending=2)
    for _ in range(5):
        adapter.parse_log_line('Failed password for test')
    assert adapter.dropped_events == 3
    assert len(adapter.collect().events) == 2
    assert not adapter.collect().events


def test_cloudtrail_denials_are_authorization_evidence_only():
    adapter = LogAdapter()
    event = adapter.ingest_json_log({'eventSource':'iam.amazonaws.com','errorCode':'AccessDenied','eventName':'ListUsers'})
    assert event.event_type == 'cloudtrail_authorization_denied'
    assert event.target_dimensions == [1]
    assert event.impact[1] < 0 and event.impact[8] == 0
    assert adapter.ingest_json_log({'eventSource':'iam.amazonaws.com','eventName':'ListUsers'}) is None
    assert adapter.ingest_json_log({'eventSource':[], 'errorCode':[]}) is None
