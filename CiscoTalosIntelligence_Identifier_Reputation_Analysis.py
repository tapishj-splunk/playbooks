"""
Accepts a URL, IP or Domain and does reputation analysis on the objects. Generates a threat level, threat categories and AUP categories that are formatted and added to a container as a note.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'input_filter' block
    input_filter(container=container)

    return

@phantom.playbook_block()
def input_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("input_filter() called")

    ################################################################################
    # Filter to pass in a url, domain or ip to it's appropriate action
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["playbook_input:url", "!=", ""]
        ],
        name="input_filter:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        url_reputation(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["playbook_input:domain", "!=", ""]
        ],
        name="input_filter:condition_2",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        domain_reputation(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    # collect filtered artifact ids and results for 'if' condition 3
    matched_artifacts_3, matched_results_3 = phantom.condition(
        container=container,
        conditions=[
            ["playbook_input:ip", "!=", ""]
        ],
        name="input_filter:condition_3",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_3 or matched_results_3:
        ip_reputation(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_3, filtered_results=matched_results_3)

    return


@phantom.playbook_block()
def url_reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("url_reputation() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Use Talos to get threat data on an url
    ################################################################################

    filtered_input_0_url = phantom.collect2(container=container, datapath=["filtered-data:input_filter:condition_1:playbook_input:url"])

    parameters = []

    # build parameters list for 'url_reputation' call
    for filtered_input_0_url_item in filtered_input_0_url:
        if filtered_input_0_url_item[0] is not None:
            parameters.append({
                "url": filtered_input_0_url_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("url reputation", parameters=parameters, name="url_reputation", assets=["cisco_talos_intelligence"], callback=url_reputation_filter)

    return


@phantom.playbook_block()
def domain_reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("domain_reputation() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Use Talos to get threat data on a domain
    ################################################################################

    filtered_input_0_domain = phantom.collect2(container=container, datapath=["filtered-data:input_filter:condition_2:playbook_input:domain"])

    parameters = []

    # build parameters list for 'domain_reputation' call
    for filtered_input_0_domain_item in filtered_input_0_domain:
        if filtered_input_0_domain_item[0] is not None:
            parameters.append({
                "domain": filtered_input_0_domain_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("domain reputation", parameters=parameters, name="domain_reputation", assets=["cisco_talos_intelligence"], callback=domain_reputation_filter)

    return


@phantom.playbook_block()
def ip_reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("ip_reputation() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Use Talos to get threat data on an ip
    ################################################################################

    filtered_input_0_ip = phantom.collect2(container=container, datapath=["filtered-data:input_filter:condition_3:playbook_input:ip"])

    parameters = []

    # build parameters list for 'ip_reputation' call
    for filtered_input_0_ip_item in filtered_input_0_ip:
        if filtered_input_0_ip_item[0] is not None:
            parameters.append({
                "ip": filtered_input_0_ip_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("ip reputation", parameters=parameters, name="ip_reputation", assets=["cisco_talos_intelligence"], callback=ip_reputation_filter)

    return


@phantom.playbook_block()
def url_reputation_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("url_reputation_filter() called")

    ################################################################################
    # Exclude failing url reputations
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["url_reputation:action_result.status", "==", "success"]
        ],
        name="url_reputation_filter:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def domain_reputation_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("domain_reputation_filter() called")

    ################################################################################
    # Exclude failing domain reputations
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["domain_reputation:action_result.status", "==", "success"]
        ],
        name="domain_reputation_filter:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_2(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def ip_reputation_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("ip_reputation_filter() called")

    ################################################################################
    # Exclude failing ip reputations
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["ip_reputation:action_result.status", "==", "success"]
        ],
        name="ip_reputation_filter:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_3(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def format_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_2() called")

    ################################################################################
    # Format output of domain threat data into an appropriate format for artifact_create
    ################################################################################

    template = """%%\n{{\"cef_data\": \n{{\"domain\": \"{0}\", \"threat level\": \"{1}\", \"threat categories\": \"{2}\", \"aup level categories\": \"{3}\"}}}}\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "domain_reputation:action_result.parameter.domain",
        "domain_reputation:action_result.data.*.Threat_Level",
        "domain_reputation:action_result.data.*.Threat_Categories",
        "domain_reputation:action_result.data.*.AUP"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_2")

    domain_artifact_create(container=container)

    return


@phantom.playbook_block()
def format_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_1() called")

    ################################################################################
    # Format output of url threat data into an appropriate format for artifact_create
    ################################################################################

    template = """%%\n{{\"cef_data\": \n{{\"url\": \"{0}\", \"threat level\": \"{1}\", \"threat categories\": \"{2}\", \"aup level categories\":\"{3}\"}}}}\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "url_reputation:action_result.parameter.url",
        "url_reputation:action_result.data.*.Threat_Level",
        "url_reputation:action_result.data.*.Threat_Categories",
        "url_reputation:action_result.data.*.AUP"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_1")

    url_artifact_create(container=container)

    return


@phantom.playbook_block()
def format_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_3() called")

    ################################################################################
    # Format output of ip threat data into an appropriate format for artifact_create
    ################################################################################

    template = """%%\n{{\"cef_data\": \n{{\"ip\": \"{0}\", \"threat level\": \"{1}\", \"threat categories\": \"{2}\", \"aup level categories\": \"{3}\"}}}}\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "ip_reputation:action_result.parameter.ip",
        "ip_reputation:action_result.data.*.Threat_Level",
        "ip_reputation:action_result.data.*.Threat_Categories",
        "ip_reputation:action_result.data.*.AUP"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_3")

    ip_artifact_create(container=container)

    return


@phantom.playbook_block()
def url_artifact_create(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("url_artifact_create() called")

    ################################################################################
    # Create new artifact with the output of the url reputation
    ################################################################################

    id_value = container.get("id", None)
    format_1__as_list = phantom.get_format_data(name="format_1__as_list")

    parameters = []

    # build parameters list for 'url_artifact_create' call
    for format_1__item in format_1__as_list:
        parameters.append({
            "name": "URL reputation results",
            "tags": None,
            "label": "cisco_talos_url_reputation",
            "severity": None,
            "cef_field": None,
            "cef_value": None,
            "container": id_value,
            "input_json": format_1__item,
            "cef_data_type": None,
            "run_automation": None,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/artifact_create", parameters=parameters, name="url_artifact_create")

    return


@phantom.playbook_block()
def domain_artifact_create(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("domain_artifact_create() called")

    ################################################################################
    # Create new artifact with the output of the domain reputation
    ################################################################################

    id_value = container.get("id", None)
    format_2__as_list = phantom.get_format_data(name="format_2__as_list")

    parameters = []

    # build parameters list for 'domain_artifact_create' call
    for format_2__item in format_2__as_list:
        parameters.append({
            "name": "Domain reputation results",
            "tags": None,
            "label": "cisco_talos_domain_reputation",
            "severity": None,
            "cef_field": None,
            "cef_value": None,
            "container": id_value,
            "input_json": format_2__item,
            "cef_data_type": None,
            "run_automation": None,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/artifact_create", parameters=parameters, name="domain_artifact_create")

    return


@phantom.playbook_block()
def ip_artifact_create(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("ip_artifact_create() called")

    ################################################################################
    # Create new artifact with the output of the ip reputation
    ################################################################################

    id_value = container.get("id", None)
    format_3__as_list = phantom.get_format_data(name="format_3__as_list")

    parameters = []

    # build parameters list for 'ip_artifact_create' call
    for format_3__item in format_3__as_list:
        parameters.append({
            "name": "IP reputation results",
            "tags": None,
            "label": "cisco_talos_ip_reputation",
            "severity": None,
            "cef_field": None,
            "cef_value": None,
            "container": id_value,
            "input_json": format_3__item,
            "cef_data_type": None,
            "run_automation": None,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/artifact_create", parameters=parameters, name="ip_artifact_create")

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    return