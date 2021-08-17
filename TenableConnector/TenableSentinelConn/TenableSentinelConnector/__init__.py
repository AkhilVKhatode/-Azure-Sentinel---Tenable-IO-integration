import json
import os
import logging
from tenable.io import TenableIO
import azure.functions as func
import base64
import hmac
import hashlib
import datetime
from datetime import date
import requests
from tenable.errors import TioExportsError, ConnectionError
import time
import arrow
from .state_manager import StateManager


TenableAccessKey = os.environ.get('TenableAccessKey')
TenableSecretKey = os.environ.get('TenableSecretKey')
customer_id = os.environ['WorkspaceID']
shared_key = os.environ['WorkspaceKey']
connection_string = os.environ['AzureWebJobsStorage']
logAnalyticsUri = os.environ.get('logAnalyticsUri')
start_time = os.environ.get('StartTime')
lowest_severity = os.environ.get("lowest_severity", "info")
tenable_tags = os.environ.get("tenable_tags")
fixed_vulnerability = os.environ.get("fixed_vulnerability")
sync_plugins = os.environ.get("sync_plugins")
verify_ssl = os.environ.get("verify_ssl")


class Tenable():

    def __init__(self):
        logging.info("_init_1")
        self.input_name = "Crest"
        self.current_time = int(time.time())
        self.start_time = start_time if start_time else "1970-01-01T00:00:00Z"
        logging.warning("Start time is {}".format(self.start_time))
        logging.info(self.start_time)
        self.start_time = arrow.get(self.start_time).timestamp()
        self.SEVERITIES = ["info", "low", "medium", "high", "critical"]
        self._severity = self.SEVERITIES[self.SEVERITIES.index(
            lowest_severity):]
        logging.info(self._severity)
        self._tags = []
        self._fixed_vulnerability = fixed_vulnerability
        self.logAnalyticsUri =  logAnalyticsUri
        self._sync_plugins = True
        logging.info("_init_2")

    # Build the API signature
    def build_signature(self, customer_id, shared_key, date, content_length, method, content_type, resource):
        x_headers = 'x-ms-date:' + date
        string_to_hash = method + "\n" + str(content_length) + "\n" + content_type + "\n" + x_headers + "\n" + resource
        bytes_to_hash = bytes(string_to_hash, encoding="utf-8")  
        decoded_key = base64.b64decode(shared_key)
        encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
        authorization = "SharedKey {}:{}".format(customer_id,encoded_hash)
        return authorization

    # Build and send a request to the POST API
    def post_data(self, body, sourcetype):
        logging.info("post_data1")
        method = 'POST'
        content_type = 'application/json'
        resource = '/api/logs'
        rfc1123date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
        content_length = len(body)
        signature = self.build_signature(customer_id, shared_key, rfc1123date, content_length, method, content_type, resource)
        
        if not self.logAnalyticsUri:
            self.logAnalyticsUri = 'https://' + customer_id + '.ods.opinsights.azure.com'
        uri = self.logAnalyticsUri + resource + '?api-version=2016-04-01'
        logging.info("In post data sourcetype {}".format(sourcetype))
        if sourcetype == "tenable:io:vuln":
            table_name = "Test_Vulns"
        elif sourcetype == "tenable:io:assets":
            table_name = "Test_Assets"
        elif sourcetype == "tenable:io:plugin":
            table_name = "Test_Plugins"

        headers = {
            'content-type': content_type,
            'Authorization': signature,
            'Log-Type': table_name,
            'x-ms-date': rfc1123date
        }
        try:
            response = requests.post(uri,data=body, headers=headers)
        except Exception as e:
            logging.info("post_data2")
            return e
        if (response.status_code >= 200 and response.status_code <= 299):
            logging.info("Data entered successfully.")
            logging.info("post_data3")
            return "Data entered successfully."
        else:
            logging.info("Failed inserting data Response code: {}".format(response.text))
            logging.info("post_data4")
            return "Failed inserting data Response code: {}".format(response.text)
    
    
    def _event_transformer(self, event, sourcetype, time_filter):
        """Transforms, modifies and updates the received json event.

        Args:
            event (dict): vuln, asset, or plugin event
            sourcetype (str): sourcetype of the event
                            e.g. tenable:io:vuln, tenable:io:assets, tenable:io:plugin
            time_filter (str): asset and plugin time field on which to store the latest event time to respective cehckpoint

        Returns:
            dict, int: transformed event and epoch time on which to index the event
        """
        logging.info("_event_transformer1")
        event["IO_address"] = "cloud.tenable.com"

        if sourcetype == "tenable:io:vuln":
            # process the event
            asset = event.pop("asset", {})
            event.update({
                "asset_uuid": asset.get("uuid"),
                "asset_fqdn": asset.get("fqdn"),
                "agent_uuid": asset.get("agent_uuid"),
                "ipv4": asset.get("ipv4"),
                "ipv6": asset.get("ipv6"),
                "vendor_severity": event.get("severity", ""),
                "state": event.get("state", "").lower()
            })
            logging.info(event)
            if event.get("state", "") == "fixed":
                # converting the date from ISO format to timestamp
                event_time = arrow.get(event.get("last_fixed")).timestamp()
            else:
                event_time = arrow.get(event.get("last_found")).timestamp()

            # we're converting severity value "info" to "informational" for consistency
            if event.get("severity", "").lower() == "info":
                event["severity"] = "informational"
            
            # if len(event.get("output", "")) > self.max_event_size:
            #     event["output"] = " ".join([
            #         "Removed the original content as the original output was",
            #         "{} characters,".format(len(event.get("output"))),
            #         "which was more than the {}".format(self.max_event_size),
            #         "character limit that was defined."
            #     ])
            checkpoint_time = event_time

        elif sourcetype == "tenable:io:assets":
            # process the event
            checkpoint_time = arrow.get(event.get(time_filter)).timestamp()
            event_time = checkpoint_time
            if time_filter == "deleted_at":
                event["state"] = "Deleted"
            elif time_filter == "terminated_at":
                event["state"] = "Terminated"
            else:
                event["state"] = "Active"
                #get and check ls 
                last_seen = event.get('last_seen')
                if not last_seen:
                    last_seen = checkpoint_time
                else:
                    last_seen = arrow.get(last_seen).timestamp()
                #get and check lst
                last_scan_time = event.get('last_scan_time')
                if not last_scan_time:
                    last_scan_time = 0
                else:
                    last_scan_time = arrow.get(last_scan_time).timestamp()
                # do comparison
                if last_scan_time > last_seen:
                    event_time = last_scan_time
                else:
                    event_time = last_seen

            event["uuid"] = event.pop("id", None)
    
        elif sourcetype == "tenable:io:plugin":
            # for plugins we have time field under attributes key  
            attrs = event.pop("attributes", {})
            event.update(attrs)
            checkpoint_time = self.current_time
            # Cant use time_filter time as many plugins are super old
            event_time = time.time()

        # Tmax_event is reset to -1 at start of each pull of data type
        self.max_event_time = max(self.max_event_time, checkpoint_time)
        logging.info("_event_transformer2")
        return event, event_time
        
    def write_event(self, event, sourcetype, time_filter):
        """Index the event into the Azure into given sourcetype.
        Events are transformed first before ingesting into the splunk.

        Args:
            event (dict): event to index
            sourcetype (str): sourcetype in which to index the events
            time_filter (str): time field value using which to save the checkpoint time
        """
        logging.info("write_event1")
        logging.info(event)
        event, event_time = self._event_transformer(event, sourcetype, time_filter)
        parsed_event = json.dumps(event)
        self.post_data(parsed_event, sourcetype)
        logging.info("write_event2")
    
    def collect_events(self):
        logging.info("collect_events1")
        
        """Collect vulnerabilities, assets, and plugins of tenable io based on given filters.
        """
        # grab all iterators at the same time and iterate them over parallely
        logging.info("Tenable.io data collection started for input: {}".format(self.input_name))
        
        
        try:
            # get active vulns
            self._get_vulns(["open", "reopened"], "last_found")
        except TioExportsError as e:
            logging.error("Tenable.io exports error occured during opened/reopened vulns data collection: {}".format(str(e)))

        try:
            # get fixed vulns
            self._get_vulns(["fixed"], "last_fixed")
        except TioExportsError as e:
            logging.error("Tenable.io exports error occured during fixed vulns data collection: {}".format(str(e)))
        
        try:
            # get active assets
            self._get_assets("updated_at")
        except TioExportsError as e:
            logging.error("Tenable.io exports error occured during active assets data collection: {}".format(str(e)))

        try:
            # get deleted assets
            self._get_assets("deleted_at")
        except TioExportsError as e:
            logging.error("Tenable.io exports error occured during deleted assets data collection: {}".format(str(e)))

        try:
            # get terminated assets
            self._get_assets("terminated_at")
        except TioExportsError as e:
            logging.error("Tenable.io exports error occured during terminated assets data collection: {}".format(str(e)))

        self._get_plugins("plugin_modification_date")
      
        logging.info("collect_events2")

    def _get_vulns(self, vuln_state, time_field):
        logging.info("get_vulns1")
        """Fetch and index vulnerability data.
        Since field in the export is the epoch time of given time field from checkpoint.

        Args:
            vuln_state (list): state of the vulnerability
                            e.g. ["open", "reopened"] OR ["fixed"]
            time_field (str): last_found - active vulns, 0 - patched vulns
        """
        logging.info("Tenable.io vulns:{} data collection started".format(time_field))
        vuln_checkpoint = self.get_checkpoint("vulns", time_field)
        # collect events for fixed state vulns only if its not first invocation or fixed vuln checkbox is checked
        is_first_invocation = not vuln_checkpoint.get("since")
        self.max_event_time = -1

        if (not self._fixed_vulnerability) and is_first_invocation and time_field == "last_fixed":
            logging.info("In if")
            vuln_checkpoint["since"] = self.current_time
            self.save_checkpoint("vulns", time_field, vuln_checkpoint)
            logging.info("Tenable.io vulns:{} data collection skipped".format(time_field))
        else:
            logging.info("In else")
            logging.info(vuln_state)
            params = {
                time_field: int(vuln_checkpoint.get("since", self.start_time)),
                # "num_assets": 500,
                "severity": self._severity,
                "state": vuln_state
                # "tags": self._tags,
            }
            logging.info("In else2")
            vulns = self._tio.exports.vulns(**params)
            logging.info("In else3 {}".format(vulns))
            i = 0
            for vuln in vulns:
                i += 1
                self.write_event(vuln, "tenable:io:vuln", time_field)
            logging.warning("Vulns count {}".format(i))
  
        if self.max_event_time != -1:
            # Adding 1 to max time for avoiding duplicate data
            vuln_checkpoint["since"] = self.max_event_time + 1
            self.save_checkpoint("vulns", time_field, vuln_checkpoint)
        logging.info("Tenable.io vulns:{} data collection completed".format(time_field))
        logging.info("get_vulns2")
    
    def _get_assets(self, time_field):
        """Fetch and index asset data.
        Since field in the export is the epoch time of given time field from checkpoint.

        Args:
            time_field (str): updated_at, deleted_at, or terminated_at
        """
        logging.info("get_assets1")
        logging.info("Tenable.io assets:{} data collection started".format(time_field))
        asset_checkpoint = self.get_checkpoint("assets", time_field)
        # collect events for deleted or terminated state assets only if its not first invocation
        is_first_invocation = not asset_checkpoint.get("since")
        self.max_event_time = -1

        if is_first_invocation and time_field in ["deleted_at", "terminated_at"]:
            asset_checkpoint["since"] = self.current_time
            self.save_checkpoint("assets", time_field, asset_checkpoint)
            logging.info("Tenable.io assets:{} data collection skipped".format(time_field))
        else:
            logging.warning("Time for assets is {}".format(int(asset_checkpoint.get("since", self.start_time))))
            params = {
                # "chunk_size": 1000,
                # "tags": self._tags,
                time_field: int(asset_checkpoint.get("since", self.start_time))
            }
            assets = self._tio.exports.assets(**params)
            i = 0
            for asset in assets:
                i += 1
                self.write_event(asset, "tenable:io:assets", time_field)
            logging.warning("Asset count {}".format(i))
        if self.max_event_time != -1:
            # Adding 1 to max time for avoiding duplicate data
            asset_checkpoint["since"] = self.max_event_time + 1
            self.save_checkpoint("assets", time_field, asset_checkpoint)
        logging.info("Tenable.io assets:{} data collection completed".format(time_field))
        logging.info("get_assets2")

    def _get_plugins(self, time_field):
        """Fetch and index plugin data.
        Since field in the export is the epoch time of given time field from checkpoint.

        Args:
            time_field (str): last_run_date
        """
        logging.info("get_plugins1")
        if not self._sync_plugins:
            logging.info("Tenable.io plugins:{} data collection skipped as sync plugin is not checked".format(time_field))
            return

        logging.info("Tenable.io plugins:{} data collection started".format(time_field))
        plugin_checkpoint = self.get_checkpoint("plugins", time_field)
        plugin_modification_time = plugin_checkpoint.get("since", self.start_time)
        plugin_modification_date = date.fromtimestamp(plugin_modification_time)
        # Only collect plugin data if the difference between current time and the last input invocation time
        # is greater or equal to 24 hrs. Added this because the API only has the fidelity of date.
        # Note: This won't prevent data duplication completely but will reduce multiple duplications to only once.
        time_diff = self.current_time - int(plugin_modification_time)
        is_first_invocation = not plugin_checkpoint.get("since")
        if not is_first_invocation and time_diff < 86400:
            logging.info("Tenable.io plugins:{} data collection skipped to reduce data duplication. "
                                 "Time diff between last invocation is: {} second(s)".format(time_field, time_diff))
            return
        plugins = self._tio.plugins.list(last_updated=plugin_modification_date)
        self.max_event_time = -1
        i = 0
        for plugin in plugins:
            i += 1
            self.write_event(plugin, "tenable:io:plugin", time_field)
        logging.warning("Plugins count {}".format(i))
        if self.max_event_time != -1:
            # Adding 1 to max time for avoiding duplicate data
            plugin_checkpoint["since"] = self.max_event_time + 1
            self.save_checkpoint("plugins", time_field, plugin_checkpoint)
        logging.info("Tenable.io plugins:{} data collection completed".format(time_field))
        logging.info("get_plugins2")


    def get_checkpoint(self, export_type, time_filter):
        logging.info("get_checkpoint1")
        """Return checkpoint based on export type and time filter field.

        Args:
            export_type (str): vulns, assets, or plugins
            time_filter (str): time field filter based on export
                                last_found - active vulns
                                last_fixed - patched vulns
                                updated_at - assets
                                deleted_at - assets
                                terminated_at - assets
                                last_run_date - plugins

        Returns:
            dict: checkpoint state dict
        """

        checkpoint_state = StateManager(connection_string,share_name=export_type,file_path=time_filter)
        state = checkpoint_state.get()
        if state:
            state = json.loads(state)
        logging.info("Check point state returned is {}".format(state))

        # in case if checkpoint is not found state value will be None,
        # so we are setting it to empty dict
        if not isinstance(state, dict):
            state = {}
        logging.info("get_checkpoint2")
        return state


    def save_checkpoint(self, export_type, time_filter, state):
        logging.info("save_checkpoint1")
        """Save checkpoint state with name formed from input name, export type, and time field.

        Args:
            export_type (str): vulns, assets, or plugins
            time_filter (str): time field filter based on export
                                last_found - active vulns
                                last_fixed - patched vulns
                                updated_at - assets
                                deleted_at - assets
                                terminated_at - assets
                                last_run_date - plugins
            state (dict): checkpoint state value
        """
        checkpoint_state = StateManager(connection_string,share_name=export_type,file_path=time_filter)
        state = json.dumps(state)
        checkpoint_state.post(state)
        logging.info("Check point state saved is " + str(state))
        logging.info("save_checkpoint2")

    def _set_input_data(self):
        logging.info("_set_input_data1")
        """Set Tenable IO input form fields and initialize tio object.
        """
        
        # we support both types tags format legacy - dictionary of key value pairs
        # and new - list of tuples of key value pairs
        # self._tags = tenable_tags if tenable_tags else []
        # if self._tags:
        #     try:
        #         # if the new tag format is used i.e [("key1", "value1"), ...] json.loads with fail with ValueError
        #         self._tags = list(json.loads(self._tags).items())
        #         self._convert_tags()
        #     except ValueError:
        #         self._tags = eval(self._tags, {"__builtins__": None}, {})
        #     except Exception as e:
        #         self._tags = []
        #         logging.error("Unexpected error occured while processing tags: {}".format(str(e)))

        # self._fixed_vulnerability = utility.is_true(self.helper.get_arg("fixed_vulnerability"))
        # self._sync_plugins = utility.is_true(self.helper.get_arg("sync_plugins"))

        try:
            self._tio = TenableIO(
                access_key=TenableAccessKey,
                secret_key=TenableSecretKey,
                # url="https://" + self._account["address"].strip("/"),
                # proxies=self.proxies,
                vendor='Tenable',
                product='TenabeAzure',
                # build=self.build
            )
            # verify_ssl = utility.is_true(self._account['verify_ssl'])
            # if not verify_ssl:
            #     self._tio._session.verify = verify_ssl
        except ConnectionError as e:
            logging.error("Tenable.io error occured while initializing connection: {}".format(str(e)))
            exit(0)
        
        if self._tio.session.details().get('permissions') < 64:
            logging.error('This integrations requires that the user we connect with is a Tenable.io Administrator. Please update the account in Tenable.io and try again.')
            exit(0)
        logging.info("_set_input_data2")



def main(mytimer: func.TimerRequest) -> None:

    utc_timestamp = datetime.datetime.utcnow().replace(
        tzinfo=datetime.timezone.utc).isoformat()

    if mytimer.past_due:
        logging.info('The timer is past due!')

    if TenableAccessKey and TenableSecretKey:
        logging.info("main1")
        tenable = Tenable()
        tenable._set_input_data()
        tenable.collect_events()
        logging.info("main2")
    else:
        logging.error("Access key and secret key not provided.")
    logging.info("Executed successfully.")
    logging.info('Python timer trigger function ran at %s', utc_timestamp)


