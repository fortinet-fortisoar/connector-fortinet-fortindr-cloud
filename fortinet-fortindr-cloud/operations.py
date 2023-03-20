""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import requests, json, os
from django.conf import settings
from connectors.core.connector import ConnectorError, get_logger
from connectors.cyops_utilities.builtins import upload_file_to_cyops
from .constants import *

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


def get_pcap_tasks(config, params):
    ndr = FortiNDR(config)
    task_uuid = params.pop('task_uuid', '')
    if task_uuid:
        endpoint = Sensors + 'pcaptasks/{0}'.format(task_uuid)
        params = {}
    else:
        endpoint = Sensors + 'pcaptasks'
        params = build_payload(params)
    response = ndr.make_rest_call(endpoint, params=params)
    return response


def download_pcap_task_file(config, params):
    ndr = FortiNDR(config)
    task_uuid = params.pop('task_uuid')
    endpoint = Sensors + 'pcaptasks/{0}/download/file'.format(task_uuid)
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
    endpoint = Sensors + 'pcaptasks/{0}/terminate'.format(task_uuid)
    response = ndr.make_rest_call(endpoint, method='PUT', params={})
    if response.get('message'):
        return response
    else:
        return {'message': 'Successfully terminated PCAP task {0}'.format(task_uuid)}


def delete_pcap_task(config, params):
    ndr = FortiNDR(config)
    task_uuid = params.get('task_uuid')
    endpoint = Sensors + 'pcaptasks/{0}'.format(task_uuid)
    response = ndr.make_rest_call(endpoint, method='DELETE', params={})
    if response.get('message'):
        return response
    else:
        return {'message': 'Successfully deleted PCAP task {0}'.format(task_uuid)}


def get_sensors(config, params):
    ndr = FortiNDR(config)
    endpoint = Sensors + 'sensors'
    include = params.get('include')
    params.update({'include': [include[i].lower() for i in range(len(include))] if include else ''})
    params = build_payload(params)
    response = ndr.make_rest_call(endpoint, params=params)
    return response


def get_devices(config, params):
    ndr = FortiNDR(config)
    endpoint = Detection + 'devices'
    status = params.get('status')
    params.update({'status': [status[i].lower() for i in range(len(status))] if status else ''})
    params.update({'sort_by': SORT_BY.get(params.get('sort_by')) if params.get('sort_by') else ''})
    params.update({'sort_order': SORT_ORDER.get(params.get('sort_order')) if params.get('sort_order') else ''})
    params = build_payload(params)
    response = ndr.make_rest_call(endpoint, params=params)
    return response


def get_events_telemetry_details(config, params):
    ndr = FortiNDR(config)
    endpoint = Sensors + 'telemetry/events'
    params.update({'interval': params.get('interval').lower() if params.get('interval') else ''})
    params.update({'event_type': EVENT_TYPE.get(params.get('event_type')) if params.get('event_type') else ''})
    params.update({'group_by': GROUP_BY.get(params.get('group_by')) if params.get('group_by') else ''})
    params = build_payload(params)
    response = ndr.make_rest_call(endpoint, params=params)
    return response


def get_network_telemetry_details(config, params):
    ndr = FortiNDR(config)
    endpoint = Sensors + 'telemetry/network_usage'
    params.update({'interval': Interval.get(params.get('interval')) if params.get('interval') else ''})
    params.update({'sort_order': SORT_ORDER.get(params.get('sort_order')) if params.get('sort_order') else ''})
    params = build_payload(params)
    response = ndr.make_rest_call(endpoint, params=params)
    return response


def get_packetstats_telemetry_details(config, params):
    ndr = FortiNDR(config)
    endpoint = Sensors + 'telemetry/packetstats'
    params.update({'interval': params.get('interval').lower() if params.get('interval') else ''})
    params.update({'group_by': GROUP_BY.get(params.get('group_by')) if params.get('group_by') else ''})
    params = build_payload(params)
    response = ndr.make_rest_call(endpoint, params=params)
    return response


def get_entity_tracking(config, params):
    ndr = FortiNDR(config)
    entity_type, entity_value = params.pop('entity_type'), params.pop('entity_value')
    if entity_type == 'IP Address':
        endpoint = Entity_Tracking + 'tracking/ip/{0}'.format(entity_value)
    elif entity_type == 'MAC Address':
        endpoint = Entity_Tracking + 'tracking/mac/{0}'.format(entity_value)
    else:
        endpoint = Entity_Tracking + 'tracking/hostname/{0}'.format(entity_value)
    params = build_payload(params)
    response = ndr.make_rest_call(endpoint, params=params)
    return response


def create_deny_list(config, params):
    ndr = FortiNDR(config)
    endpoint = Entity_Tracking + 'tracking/ip_blacklist'
    payload = build_payload(params)
    response = ndr.make_rest_call(endpoint, 'POST', data=json.dumps(payload))
    return response


def get_deny_list(config, params):
    ndr = FortiNDR(config)
    endpoint = Entity_Tracking + 'tracking/ip_blacklist/{0}'.format(params.get('account_uuid'))
    response = ndr.make_rest_call(endpoint, params={})
    return response


def update_deny_list(config, params):
    ndr = FortiNDR(config)
    account_uuid = params.pop('account_uuid')
    endpoint = Entity_Tracking + 'tracking/ip_blacklist/{0}'.format(account_uuid)
    payload = build_payload(params)
    response = ndr.make_rest_call(endpoint, method='PUT', data=json.dumps(payload))
    if response.get('message'):
        return response
    else:
        return {'message': 'Successfully updated deny list {0}'.format(account_uuid)}


def delete_deny_list(config, params):
    ndr = FortiNDR(config)
    account_uuid = params.get('account_uuid')
    endpoint = Entity_Tracking + 'tracking/ip_blacklist/{0}'.format(account_uuid)
    response = ndr.make_rest_call(endpoint, method='DELETE', params={})
    if response.get('message'):
        return response
    else:
        return {'message': 'Successfully deleted deny list {0}'.format(account_uuid)}


def delete_ip_from_deny_list(config, params):
    ndr = FortiNDR(config)
    account_uuid = params.get('account_uuid')
    ip = params.get('ip')
    endpoint = Entity_Tracking + 'tracking/ip_blacklist/{0}/{1}'.format(account_uuid, ip)
    response = ndr.make_rest_call(endpoint, method='DELETE', params={})
    if response.get('message'):
        return response
    else:
        return {'message': 'Successfully deleted IP {0} from deny list {1}'.format(ip, account_uuid)}


def get_entity_summary(config, params):
    ndr = FortiNDR(config)
    endpoint = Entity + '{0}/summary'.format(params.get('entity'))
    response = ndr.make_rest_call(endpoint, params={})
    return response


def get_entity_pdns(config, params):
    ndr = FortiNDR(config)
    endpoint = Entity + '{0}/pdns'.format(params.pop('entity'))
    params = build_payload(params)
    response = ndr.make_rest_call(endpoint, params=params)
    return response


def get_events(config, params):
    ndr = FortiNDR(config)
    endpoint = Detection + 'events'
    params = build_payload(params)
    response = ndr.make_rest_call(endpoint, params=params)
    return response


def get_indicators(config, params):
    ndr = FortiNDR(config)
    endpoint = Detection + 'indicators/rule_counts'
    detection_status = params.get('detection_status')
    params.update({'detection_status': [detection_status[i].lower() for i in
                                        range(len(detection_status))] if detection_status else ['active']})
    params.update({'sort_order': SORT_ORDER.get(params.get('sort_order')) if params.get('sort_order') else ''})
    params = build_payload(params)
    response = ndr.make_rest_call(endpoint, params=params)
    return response


def get_detections(config, params):
    ndr = FortiNDR(config)
    endpoint = Detection + 'detections'
    status, include = params.get('status'), params.get('include')
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
    endpoint = Detection + 'detections/{0}/resolve'.format(detection_uuid)
    params.update({'resolution': Resolution.get(params.get('resolution')) if params.get('resolution') else ''})
    payload = build_payload(params)
    response = ndr.make_rest_call(endpoint, method='PUT', data=json.dumps(payload))
    if response.get('message'):
        return response
    else:
        return {"message": "Successfully resolved detection {0}".format(detection_uuid)}


def get_detection_rules(config, params):
    ndr = FortiNDR(config)
    endpoint = Detection + 'rules'
    severity, confidence, category = params.get('severity'), params.get('confidence'), params.get('category')
    params.update({'sort_by': SORT_BY.get(params.get('sort_by')) if params.get('sort_by') else ''})
    params.update({'sort_order': SORT_ORDER.get(params.get('sort_order')) if params.get('sort_order') else ''})
    params.update({'severity': [severity[i].lower() for i in range(len(severity))] if severity else ''})
    params.update({'confidence': [confidence[i].lower() for i in range(len(confidence))] if confidence else ''})
    params.update({'category': [category[i].lower() for i in range(len(category))] if category else ''})
    params = build_payload(params)
    response = ndr.make_rest_call(endpoint, params=params)
    return response


def get_detection_rule_details(config, params):
    ndr = FortiNDR(config)
    rule_uuid = params.pop('rule_uuid')
    endpoint = Detection + 'rules/{0}'.format(rule_uuid)
    params = build_payload(params)
    response = ndr.make_rest_call(endpoint, params=params)
    return response


def get_detection_rule_events(config, params):
    ndr = FortiNDR(config)
    endpoint = Detection + 'rules/{0}/events'.format(params.pop('rule_uuid'))
    params = build_payload(params)
    response = ndr.make_rest_call(endpoint, params=params)
    return response


def login(config, params):
    ndr = FortiNDR(config)
    endpoint = Sensors + 'sensors'
    headers = {'Content-Type': 'application/json', 'Authorization': 'IBToken ' + ndr.api_key}
    response = requests.request(method='GET', url=endpoint, headers=headers, verify=ndr.verify_ssl)
    if response.ok:
        return response.json()
    else:
        raise ConnectorError('Invalid Credentials')


def _check_health(config):
    try:
        response = login(config, params={})
        if response:
            return True
    except Exception as err:
        raise ConnectorError("{0}".format(str(err)))


operations = {
    'get_events': get_events,
    'get_indicators': get_indicators,
    'get_pcap_tasks': get_pcap_tasks,
    'download_pcap_task_file': download_pcap_task_file,
    'terminate_pcap_task': terminate_pcap_task,
    'delete_pcap_task': delete_pcap_task,
    'get_sensors': get_sensors,
    'get_devices': get_devices,
    'get_events_telemetry_details': get_events_telemetry_details,
    'get_network_telemetry_details': get_network_telemetry_details,
    'get_packetstats_telemetry_details': get_packetstats_telemetry_details,
    'get_entity_tracking': get_entity_tracking,
    'create_deny_list': create_deny_list,
    'get_deny_list': get_deny_list,
    'update_deny_list': update_deny_list,
    'delete_deny_list': delete_deny_list,
    'delete_ip_from_deny_list': delete_ip_from_deny_list,
    'get_entity_summary': get_entity_summary,
    'get_entity_pdns': get_entity_pdns,
    'get_detections': get_detections,
    'resolve_detection': resolve_detection,
    'get_detection_rules': get_detection_rules,
    'get_detection_rule_details': get_detection_rule_details,
    'get_detection_rule_events': get_detection_rule_events
}
