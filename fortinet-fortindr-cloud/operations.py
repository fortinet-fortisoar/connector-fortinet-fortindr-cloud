"""
Copyright start
MIT License
Copyright (c) 2026 Fortinet Inc
Copyright end
"""

import requests, json, os
from django.conf import settings
from connectors.core.connector import ConnectorError, get_logger
from .constants import *

try:
    from connectors.cyops_utilities.builtins import upload_file_to_cyops
except:
    pass

logger = get_logger('fortinet-fortindr-cloud')


class FortiNDR(object):
    def __init__(self, config, *args, **kwargs):
        self.api_key = config.get('api_key')
        self.verify_ssl = config.get('verify_ssl')

    def make_rest_call(self, url, method='GET', data=None, params=None):
        try:
            headers = {
                'Authorization': 'IBToken ' + self.api_key,
                'Content-Type': 'application/json'
            }
            logger.debug("Endpoint {0}".format(url))
            response = requests.request(method, url, data=data, params=params,
                                        headers=headers,
                                        verify=self.verify_ssl)
            logger.debug("response_content {0}:{1}".format(response.status_code, response.content))
            if response.ok or response.status_code == 204:
                logger.info('Successfully got response for url {0}'.format(url))
                if 'json' in str(response.headers):
                    return response.json()
                else:
                    return dict()
            elif response.status_code == 404:
                return {"message": "Not Found"}
            elif response.status_code == 500:
                raise ConnectorError("Internal Server Error")
            else:
                raise ConnectorError("{0}".format(response.content))
        except requests.exceptions.SSLError:
            raise ConnectorError('SSL certificate validation failed')
        except requests.exceptions.ConnectTimeout:
            raise ConnectorError('The request timed out while trying to connect to the server')
        except requests.exceptions.ReadTimeout:
            raise ConnectorError(
                'The server did not send any data in the allotted amount of time')
        except requests.exceptions.ConnectionError:
            raise ConnectorError('Invalid Credentials')
        except Exception as err:
            raise ConnectorError(str(err))


def build_payload(payload):
    payload = {k: v for k, v in payload.items() if v is not None and v != ''}
    return payload


def sensor_cloud_region(config):
    if config.get('cloud_region') == "US Region":
        cloud_region = US_Sensors
    else:
        cloud_region = EU_Sensors
    return cloud_region


def detection_cloud_region(config):
    if config.get('cloud_region') == "US Region":
        cloud_region = US_Detection
    else:
        cloud_region = EU_Detection
    return cloud_region


def annotation_cloud_region(config):
    if config.get('cloud_region') == "US Region":
        cloud_region = US_Annotation
    else:
        cloud_region = EU_Annotation
    return cloud_region


def annotation_bulk_cloud_region(config):
    if config.get('cloud_region') == "US Region":
        cloud_region = US_Annotation_Bulk
    else:
        cloud_region = EU_Annotation_Bulk
    return cloud_region


def entity_cloud_region(config):
    if config.get('cloud_region') == "US Region":
        cloud_region = US_Entity
    else:
        cloud_region = EU_Entity
    return cloud_region


def entity_tracking_cloud_region(config):
    if config.get('cloud_region') == "US Region":
        cloud_region = US_Entity_Tracking
    else:
        cloud_region = EU_Entity_Tracking
    return cloud_region


def get_pcap_tasks(config, params):
    ndr = FortiNDR(config)
    task_uuid = params.pop('task_uuid', '')
    cloud_region = sensor_cloud_region(config)
    if task_uuid:
        endpoint = cloud_region + 'pcaptasks/{0}'.format(task_uuid)
        params = {}
    else:
        endpoint = cloud_region + 'pcaptasks'
        params = build_payload(params)
    response = ndr.make_rest_call(endpoint, params=params)
    return response


def download_pcap_task_file(config, params):
    ndr = FortiNDR(config)
    task_uuid = params.pop('task_uuid')
    cloud_region = sensor_cloud_region(config)
    endpoint = cloud_region + 'pcaptasks/{0}/download/file'.format(task_uuid)
    params = build_payload(params)
    response = ndr.make_rest_call(endpoint, params=params)
    try:
        if response.get('message'):
            return response
    except:
        file_name = response[1]
        path = os.path.join(settings.TMP_FILE_ROOT, file_name)
        logger.error("Path: {0}".format(path))
        with open(path, 'wb') as fp:
            fp.write(response[0])
        attach_response = upload_file_to_cyops(file_path=file_name, filename=file_name,
                                               name=file_name, create_attachment=True)
        return attach_response


def terminate_pcap_task(config, params):
    ndr = FortiNDR(config)
    task_uuid = params.get('task_uuid')
    cloud_region = sensor_cloud_region(config)
    endpoint = cloud_region + 'pcaptasks/{0}/terminate'.format(task_uuid)
    response = ndr.make_rest_call(endpoint, method='PUT', params={})
    if response.get('message'):
        return response
    else:
        return {'message': 'Successfully terminated PCAP task {0}'.format(task_uuid)}


def delete_pcap_task(config, params):
    ndr = FortiNDR(config)
    task_uuid = params.get('task_uuid')
    cloud_region = sensor_cloud_region(config)
    endpoint = cloud_region + 'pcaptasks/{0}'.format(task_uuid)
    response = ndr.make_rest_call(endpoint, method='DELETE', params={})
    if response.get('message'):
        return response
    else:
        return {'message': 'Successfully deleted PCAP task {0}'.format(task_uuid)}


def get_sensors(config, params):
    ndr = FortiNDR(config)
    cloud_region = sensor_cloud_region(config)
    endpoint = cloud_region + 'sensors'
    include = params.get('include')
    params.update({'account_uuid': config.get('account_uuid') if config.get('account_uuid') else ''})
    params.update({'include': [include[i].lower() for i in range(len(include))] if include else ''})
    params = build_payload(params)
    response = ndr.make_rest_call(endpoint, params=params)
    return response


def get_devices_with_detection(config, params):
    ndr = FortiNDR(config)
    cloud_region = detection_cloud_region(config)
    endpoint = cloud_region + 'devices'
    status = params.get('status')
    params.update(
        {'account_uuid': params.get('account_uuid') or config.get('account_uuid') or ''})
    params.update({'status': [status[i].lower() for i in range(len(status))] if status else ''})
    params.update({'sort_by': SORT_BY.get(params.get('sort_by')) if params.get('sort_by') else ''})
    params.update({'sort_order': SORT_ORDER.get(params.get('sort_order')) if params.get('sort_order') else ''})
    params = build_payload(params)
    response = ndr.make_rest_call(endpoint, params=params)
    return response


def get_telemetry_events(config, params):
    ndr = FortiNDR(config)
    cloud_region = sensor_cloud_region(config)
    endpoint = cloud_region + 'telemetry/events'
    params.update({'account_uuid': config.get('account_uuid') if config.get('account_uuid') else ''})
    params.update({'interval': params.get('interval').lower() if params.get('interval') else ''})
    params.update({'event_type': EVENT_TYPE.get(params.get('event_type')) if params.get('event_type') else ''})
    params.update({'group_by': GROUP_BY.get(params.get('group_by')) if params.get('group_by') else ''})
    params = build_payload(params)
    response = ndr.make_rest_call(endpoint, params=params)
    return response


def get_telemetry_bandwidth(config, params):
    ndr = FortiNDR(config)
    cloud_region = sensor_cloud_region(config)
    endpoint = cloud_region + 'telemetry/network_usage'
    params.update({'interval': Interval.get(params.get('interval')) if params.get('interval') else ''})
    params.update({'sort_order': SORT_ORDER.get(params.get('sort_order')) if params.get('sort_order') else ''})
    params = build_payload(params)
    response = ndr.make_rest_call(endpoint, params=params)
    return response


def get_telemetry_packetstats(config, params):
    ndr = FortiNDR(config)
    cloud_region = sensor_cloud_region(config)
    endpoint = cloud_region + 'telemetry/packetstats'
    params.update({'interval': params.get('interval').lower() if params.get('interval') else ''})
    params.update({'group_by': GROUP_BY.get(params.get('group_by')) if params.get('group_by') else ''})
    params = build_payload(params)
    response = ndr.make_rest_call(endpoint, params=params)
    return response


def get_entity_tracking(config, params):
    ndr = FortiNDR(config)
    entity_type, entity_value = params.pop('entity_type'), params.pop('entity_value')
    cloud_region = entity_tracking_cloud_region(config)
    if entity_type == 'IP Address':
        endpoint = cloud_region + 'tracking/ip/{0}'.format(entity_value)
    elif entity_type == 'MAC Address':
        endpoint = cloud_region + 'tracking/mac/{0}'.format(entity_value)
    else:
        endpoint = cloud_region + 'tracking/hostname/{0}'.format(entity_value)
    params.update({'account_uuid': config.get('account_uuid') if config.get('account_uuid') else ''})
    params = build_payload(params)
    response = ndr.make_rest_call(endpoint, params=params)
    return response


def get_entity_summary(config, params):
    ndr = FortiNDR(config)
    cloud_region = entity_cloud_region(config)
    endpoint = cloud_region + '{0}/summary'.format(params.get('entity'))
    response = ndr.make_rest_call(endpoint, params={})
    return response


def get_entity_pdns(config, params):
    ndr = FortiNDR(config)
    cloud_region = entity_cloud_region(config)
    endpoint = cloud_region + '{0}/pdns'.format(params.pop('entity'))
    params.update({'account_uuid': config.get('account_uuid') if config.get('account_uuid') else ''})
    params = build_payload(params)
    response = ndr.make_rest_call(endpoint, params=params)
    return response


def get_detection_events(config, params):
    ndr = FortiNDR(config)
    cloud_region = detection_cloud_region(config)
    endpoint = cloud_region + 'events'
    params = build_payload(params)
    response = ndr.make_rest_call(endpoint, params=params)
    return response


def get_detection_rule_indicators(config, params):
    ndr = FortiNDR(config)
    cloud_region = detection_cloud_region(config)
    endpoint = cloud_region + 'indicators/rule_counts'
    detection_status = params.get('detection_status')
    params.update({'detection_status': [detection_status[i].lower() for i in
                                        range(len(detection_status))] if detection_status else ['active']})
    params.update({'sort_order': SORT_ORDER.get(params.get('sort_order')) if params.get('sort_order') else ''})
    params = build_payload(params)
    response = ndr.make_rest_call(endpoint, params=params)
    return response


def get_detections(config, params):
    ndr = FortiNDR(config)
    cloud_region = detection_cloud_region(config)
    endpoint = cloud_region + 'detections'
    status, include = params.get('status'), params.get('include')
    params.update({'account_uuid': config.get('account_uuid') if config.get('account_uuid') else ''})
    params.update({'status': [status[i].lower() for i in range(len(status))] if status else ['active']})
    params.update({'include': [include[i].lower() for i in range(len(include))] if include else ''})
    params.update({'sort_by': SORT_BY.get(params.get('sort_by')) if params.get('sort_by') else ''})
    params.update({'sort_order': SORT_ORDER.get(params.get('sort_order')) if params.get('sort_order') else ''})
    params = build_payload(params)
    response = ndr.make_rest_call(endpoint, params=params)
    return response


def resolve_detection(config, params):
    ndr = FortiNDR(config)
    detection_uuid = params.pop('detection_uuid')
    cloud_region = detection_cloud_region(config)
    endpoint = cloud_region + 'detections/{0}/resolve'.format(detection_uuid)
    params.update({'resolution': Resolution.get(params.get('resolution')) if params.get('resolution') else ''})
    payload = build_payload(params)
    response = ndr.make_rest_call(endpoint, method='PUT', data=json.dumps(payload))
    if response.get('message'):
        return response
    else:
        return {"message": "Successfully resolved detection {0}".format(detection_uuid)}


def get_detection_rules(config, params):
    ndr = FortiNDR(config)
    cloud_region = detection_cloud_region(config)
    endpoint = cloud_region + 'rules'
    severity, confidence, category = params.get('severity'), params.get('confidence'), params.get('category')
    params.update({'account_uuid': config.get('account_uuid') if config.get('account_uuid') else ''})
    params.update({'sort_by': SORT_BY.get(params.get('sort_by')) if params.get('sort_by') else ''})
    params.update({'sort_order': SORT_ORDER.get(params.get('sort_order')) if params.get('sort_order') else ''})
    params.update({'severity': severity.lower() if severity else ''})
    params.update({'confidence': confidence.lower() if confidence else ''})
    params.update({'category': category if category else ''})
    params = build_payload(params)
    response = ndr.make_rest_call(endpoint, params=params)
    return response


def get_detection_rule_details(config, params):
    ndr = FortiNDR(config)
    rule_uuid = params.pop('rule_uuid')
    cloud_region = detection_cloud_region(config)
    endpoint = cloud_region + 'rules/{0}'.format(rule_uuid)
    params = build_payload(params)
    response = ndr.make_rest_call(endpoint, params=params)
    return response


def get_detection_rule_events(config, params):
    ndr = FortiNDR(config)
    cloud_region = detection_cloud_region(config)
    endpoint = cloud_region + 'rules/{0}/events'.format(params.pop('rule_uuid'))
    params.update({'account_uuid': config.get('account_uuid') if config.get('account_uuid') else ''})
    params = build_payload(params)
    response = ndr.make_rest_call(endpoint, params=params)
    return response


def add_annotation(config, params):
    ndr = FortiNDR(config)
    cloud_region = annotation_cloud_region(config)
    endpoint = cloud_region
    params.update(
        {'account_uuid': params.get('account_uuid') or config.get('account_uuid') or ''})
    data = build_payload(params)
    response = ndr.make_rest_call(endpoint, method="POST", data=json.dumps(data), params={})
    return response


def retrieve_annotations(config, params):
    ndr = FortiNDR(config)
    cloud_region = annotation_cloud_region(config)
    endpoint = cloud_region
    params = build_payload(params)
    response = ndr.make_rest_call(endpoint, params=params)
    return response


def modify_annotation(config, params):
    ndr = FortiNDR(config)
    cloud_region = annotation_cloud_region(config)
    endpoint = cloud_region + '{0}'.format(params.pop('annotation_uuid'))
    data = build_payload(params.get('annotation'))
    response = ndr.make_rest_call(endpoint, method="PUT", data=json.dumps(data), params={})
    return response


def delete_annotation(config, params):
    ndr = FortiNDR(config)
    cloud_region = annotation_cloud_region(config)
    endpoint = cloud_region + '{0}'.format(params.get('annotation_uuid'))
    response = ndr.make_rest_call(endpoint, method="DELETE", params={})
    if response:
        return {"result": "Annotation not found"}
    else:
        return {"result": "Successfully deleted the annotation: {0}".format(params.get('annotation_uuid'))}


def retrieve_annotation_for_entities(config, params):
    ndr = FortiNDR(config)
    cloud_region = annotation_bulk_cloud_region(config)
    endpoint = cloud_region + 'annotation_by_entity'
    data = build_payload(params)
    response = ndr.make_rest_call(endpoint, method="POST", data=json.dumps(data), params={})
    return response


def add_or_replace_entities_to_annotation(config, params):
    ndr = FortiNDR(config)
    cloud_region = annotation_cloud_region(config)
    endpoint = cloud_region + '{0}/entity'.format(params.pop('annotation_uuid'))
    data = {
        "entities": params.pop('entities')
    }
    response = ndr.make_rest_call(endpoint, method="POST", data=json.dumps(data), params=params)
    return response


def execute_an_api_call(config, params):
    try:
        ndr = FortiNDR(config)
        endpoint = params.get("endpoint")
        headers = {'Content-Type': 'application/json', 'Authorization': 'IBToken ' + ndr.api_key}
        http_method = params.get("method")
        query_params = params.get("query_params") if params.get("query_params") else {}
        payload = json.dumps(params.get("payload")) if params.get("payload") else {}
        logger.debug("Payload: {0}".format(payload))
        response = requests.request(method=http_method, url=endpoint, headers=headers, data=payload, params=query_params, verify=ndr.verify_ssl)
        if response.ok or response.status_code == 204:
            if 'json' in str(response.headers):
                return response.json()
            else:
                return dict()
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def login(config, params):
    ndr = FortiNDR(config)
    cloud_region = sensor_cloud_region(config)
    endpoint = cloud_region + 'sensors'
    headers = {'Content-Type': 'application/json', 'Authorization': 'IBToken ' + ndr.api_key}
    response = requests.request(method='GET', url=endpoint, headers=headers, verify=ndr.verify_ssl)
    if response.ok:
        return response.json()
    else:
        raise ConnectorError('Invalid Credentials')


def _check_health(config):
    try:
        response = get_sensors(config, params={'account_uuid': config.get('account_uuid')}) if config.get(
            'account_uuid') else login(config, params={})
        if response and response.get("sensors") is not None:
            return True
        else:
            raise ConnectorError('Invalid Account UUID')
    except Exception as err:
        raise ConnectorError("{0}".format(str(err)))


operations = {
    'get_detection_events': get_detection_events,
    'get_detection_rule_indicators': get_detection_rule_indicators,
    'get_pcap_tasks': get_pcap_tasks,
    'download_pcap_task_file': download_pcap_task_file,
    'terminate_pcap_task': terminate_pcap_task,
    'delete_pcap_task': delete_pcap_task,
    'get_sensors': get_sensors,
    'get_devices_with_detection': get_devices_with_detection,
    'get_telemetry_events': get_telemetry_events,
    'get_telemetry_bandwidth': get_telemetry_bandwidth,
    'get_telemetry_packetstats': get_telemetry_packetstats,
    'get_entity_tracking': get_entity_tracking,
    'get_entity_summary': get_entity_summary,
    'get_entity_pdns': get_entity_pdns,
    'get_detections': get_detections,
    'resolve_detection': resolve_detection,
    'get_detection_rules': get_detection_rules,
    'get_detection_rule_details': get_detection_rule_details,
    'get_detection_rule_events': get_detection_rule_events,
    'add_annotation': add_annotation,
    'retrieve_annotations': retrieve_annotations,
    'modify_annotation': modify_annotation,
    'delete_annotation': delete_annotation,
    'retrieve_annotation_for_entities': retrieve_annotation_for_entities,
    'add_or_replace_entities_to_annotation': add_or_replace_entities_to_annotation,
    'execute_an_api_call': execute_an_api_call
}
