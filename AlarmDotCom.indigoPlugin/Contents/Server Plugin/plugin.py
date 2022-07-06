#! /usr/bin/env python
# -*- coding: utf-8 -*-

import indigo
import logging
import json
import time
import threading
import asyncio
try:
    from aiohttp import ClientSession
    import pyalarmdotcomajax
except ImportError:
    raise ImportError("'Required Python libraries missing.  Run 'pip3 install pyalarmdotcomajax aiohttp' in Terminal window, then reload plugin.")

from pyalarmdotcomajax import AlarmController
from pyalarmdotcomajax import AuthResult
from pyalarmdotcomajax.devices import Camera
from pyalarmdotcomajax.devices import DEVICE_URLS
from pyalarmdotcomajax.devices import DeviceType
from pyalarmdotcomajax.devices import GarageDoor
from pyalarmdotcomajax.devices import ImageSensor
from pyalarmdotcomajax.devices import Light
from pyalarmdotcomajax.devices import Lock
from pyalarmdotcomajax.devices import Partition
from pyalarmdotcomajax.devices import Sensor
from pyalarmdotcomajax.devices import System
from pyalarmdotcomajax.errors import AuthenticationFailed
from pyalarmdotcomajax.errors import DataFetchFailed
from pyalarmdotcomajax.errors import InvalidConfigurationOption
from pyalarmdotcomajax.errors import NagScreen
from pyalarmdotcomajax.errors import UnexpectedDataStructure
from pyalarmdotcomajax.extensions import ConfigurationOption
from pyalarmdotcomajax.helpers import ExtendedEnumMixin
from pyalarmdotcomajax.helpers import slug_to_title

# Homekit Support

HK_ALARM_STAY_ARMED = 0
HK_ALARM_AWAY_ARMED = 1
HK_ALARM_NIGHT_ARMED = 2
HK_ALARM_DISARMED = 3
HK_ALARM_TRIGGERED = 4
HOMEKIT_STATE = {
    Partition.DeviceState.UNKNOWN:      HK_ALARM_DISARMED,
    Partition.DeviceState.DISARMED:     HK_ALARM_DISARMED,
    Partition.DeviceState.ARMED_STAY:   HK_ALARM_STAY_ARMED,
    Partition.DeviceState.ARMED_AWAY:   HK_ALARM_AWAY_ARMED,
    Partition.DeviceState.ARMED_NIGHT:  HK_ALARM_NIGHT_ARMED,
}

class Plugin(indigo.PluginBase):

    def __init__(self, pluginId, pluginDisplayName, pluginVersion, pluginPrefs):
        indigo.PluginBase.__init__(self, pluginId, pluginDisplayName, pluginVersion, pluginPrefs)

        pfmt = logging.Formatter('%(asctime)s.%(msecs)03d\t[%(levelname)8s] %(name)20s.%(funcName)-25s%(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        self.plugin_file_handler.setFormatter(pfmt)
        self.logLevel = int(pluginPrefs.get("logLevel", 20))
        self.indigo_log_handler.setLevel(self.logLevel)
        self.plugin_file_handler.setLevel(self.logLevel)
        self.logger.debug(f"LogLevel = {self.logLevel}")

        self.pluginPrefs = pluginPrefs
        self.event_loop = None
        self.async_thread = None
        self.alarm = None
        self.session = None
        self.otp_code = None
        self.auth_state = None

        self.known_systems = {}
        self.known_partitions = {}
        self.known_sensors = {}

        self.active_systems = {}
        self.active_partitions = {}
        self.active_sensors = {}

        self.system_refresh_task: asyncio.Task | None = None

        self.updateFrequency = float(self.pluginPrefs.get('updateFrequency', "15")) * 60.0
        self.logger.debug(f"updateFrequency = {self.updateFrequency}")

    def validatePrefsConfigUi(self, valuesDict):
        self.logger.threaddebug(f"validatePrefsConfigUi, valuesDict = {valuesDict}")
        errorDict = indigo.Dict()
        valuesDict['auth_code'] = ""
        username = valuesDict.get('username', None)
        if not username or not len(username):
            errorDict['username'] = "Username is required"
        password = valuesDict.get('password', None)
        if not password or not len(password):
            errorDict['password'] = "Password is required"
        update = valuesDict.get('updateFrequency', None)
        if not update or float(update) < 3.0:
            errorDict['updateFrequency'] = "Update frequency must be at least 3 minutes"
        if len(errorDict) > 0:
            return False, valuesDict, errorDict
        return True, valuesDict

    def closedPrefsConfigUi(self, valuesDict, userCancelled):
        self.logger.threaddebug(f"closedPrefsConfigUi, valuesDict = {valuesDict}")
        if not userCancelled:
            self.logLevel = int(valuesDict.get("logLevel", logging.INFO))
            self.indigo_log_handler.setLevel(self.logLevel)
            self.plugin_file_handler.setLevel(self.logLevel)
            self.logger.debug(f"LogLevel = {self.logLevel}")
            self.updateFrequency = float(valuesDict.get('updateFrequency', "15")) * 60.0
            self.logger.debug(f"updateFrequency = {self.updateFrequency}")

    def startup(self):
        self.logger.debug("startup")
        self.async_thread = threading.Thread(target=self.run_async_thread)
        self.async_thread.start()
        self.logger.debug("startup complete")

    def run_async_thread(self):
        self.logger.debug("run_async_thread starting")
        self.event_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.event_loop)
        self.event_loop.run_until_complete(self.async_main())
        self.event_loop.close()
        self.logger.debug("run_async_thread ending")

    def verify_otp(self, valuesDict, typeId):
        self.logger.threaddebug(f"verify_otp typeId = {typeId}, valuesDict = {valuesDict}")
        self.otp_code = valuesDict['auth_code']
        valuesDict['auth_code'] = ""  # clear the code
        self.event_loop.create_task(self.async_verify_otp())
        return valuesDict

    # action from Config dialog to verify OTP code
    async def async_verify_otp(self):
        self.logger.debug(f"async_verify_otp, code = {self.otp_code}")
        try:
            generated_2fa_cookie = await self.alarm.async_submit_otp(code=self.otp_code, device_name="Indigo.Plugin")
        except Exception as err:
            self.logger.warning(f"Alarm.com OTP verification failed: {err}")
        else:
            self.logger.debug(f"async_verify_otp: generated_2fa_cookie = {generated_2fa_cookie}")
            self.pluginPrefs["twofactorcookie"] = generated_2fa_cookie
            indigo.server.savePluginPrefs()
            self.auth_state = await self.alarm.async_login()
            self.logger.debug(f"Alarm.com self.auth_state = {self.auth_state}")

    ##############################################################################################

    async def async_main(self):
        self.logger.debug("async_main starting")
        while True:
            if self.pluginPrefs.get('username', None) and self.pluginPrefs.get('password', None):
                break
            await asyncio.sleep(2)  # wait for prefs to be set

        """Create the aiohttp session and run."""
        async with ClientSession() as self.session:

            try:
                self.alarm = AlarmController(username=self.pluginPrefs.get("username"), password=self.pluginPrefs.get("password"),
                                    websession=self.session, twofactorcookie=self.pluginPrefs.get("twofactorcookie", None))
            except Exception as err:
                self.logger.error(f"AlarmController creation failed: {err}")
                return

            try:
                self.auth_state = await self.alarm.async_login()
            except NagScreen:
                self.logger.warning("Alarm.com login failed - Two-factor authentication required")
                return
            except Exception as err:
                self.logger.error(f"Alarm.com login failed: {err}")
                return

            self.logger.debug(f"Alarm.com self.auth_state = {self.auth_state}")

            if self.alarm and self.auth_state == AuthResult.OTP_REQUIRED:
                self.logger.warning("Alarm.com authentication in progress - enter OTP code in plugin menu Authenticate...")

            elif self.alarm and self.auth_state == AuthResult.ENABLE_TWO_FACTOR:
                self.logger.warning("Alarm.com authentication failed - Two-factor authentication required")
                return

            while not self.alarm or self.auth_state != AuthResult.SUCCESS:
                await asyncio.sleep(1.0)

            self.logger.info(f"Alarm.com authentication successful")
            self.logger.debug(f"Alarm.com Provider: {self.alarm.provider_name}")
            self.logger.debug(f"Logged in as: {self.alarm.user_email} ({self.alarm.user_id})")

            self.system_refresh_task = asyncio.create_task(self.async_system_refresh_loop())

            while True:
                await asyncio.sleep(1.0)
                if self.stopThread:
                    self.logger.debug("async_main: stopping")
                    break

    ##################
    # Device Methods
    ##################

    def getDeviceConfigUiValues(self, pluginProps, typeId, devId):
        self.logger.threaddebug(f"getDeviceConfigUiValues, typeId = {typeId}, devId = {devId}, pluginProps = {pluginProps}")
        valuesDict = indigo.Dict(pluginProps)
        errorsDict = indigo.Dict()

        # pre-load system and partition values where appropriate
        if typeId != "system" and "system" not in valuesDict and len(self.known_systems) > 0:
            valuesDict["system"] = list(self.known_systems.keys())[0]
        if typeId == "sensor" and "partition" not in valuesDict and "system" in valuesDict and len(self.known_partitions) > 0:
            valuesDict["partition"] = list(self.known_partitions[valuesDict['system']].keys())[0]

        return valuesDict, errorsDict

    def validateDeviceConfigUi(self, valuesDict, typeId, devId):
        self.logger.threaddebug(f"validateDeviceConfigUi, typeId = {typeId}, devId = {devId}, valuesDict = {valuesDict}")
        errorsDict = indigo.Dict()
        if len(errorsDict) > 0:
            return False, valuesDict, errorsDict
        return True, valuesDict

    def deviceStartComm(self, device):
        self.logger.debug(f"{device.name}: Starting Device")
        if device.deviceTypeId == "system":
            self.active_systems[device.id] = device.name
            self.update_system_device(device)
        elif device.deviceTypeId == "partition":
            self.active_partitions[device.id] = device.name
            self.update_partition_device(device)
        elif device.deviceTypeId == "sensor":
            self.active_sensors[device.id] = device.name
            self.update_sensor_device(device)
        device.stateListOrDisplayStateIdChanged()

    def deviceStopComm(self, device):
        self.logger.debug(f"{device.name}: Stopping Device")
        if device.deviceTypeId == "system":
            del self.active_systems[device.id]
        elif device.deviceTypeId == "partition":
            del self.active_partitions[device.id]
        elif device.deviceTypeId == "sensor":
            del self.active_sensors[device.id]

    ########################################
    # callbacks from device creation UI
    ########################################

    def get_system_list(self, filter="", valuesDict=None, typeId="", targetId=0):
        self.logger.threaddebug(f"get_system_list: typeId = {typeId}, targetId = {targetId}, filter = {filter}, valuesDict = {valuesDict}")
        systems = [
            (system.id_, system.name)
            for system in self.known_systems.values()
        ]
        self.logger.debug(f"get_system_list: systems = {systems}")
        return systems

    def get_partition_list(self, filter="", valuesDict=None, typeId="", targetId=0):
        self.logger.threaddebug(f"get_partition_list: typeId = {typeId}, targetId = {targetId}, filter = {filter}, valuesDict = {valuesDict}")
        try:
            partitions = [
                (partition.id_, partition.name)
                for partition in self.known_partitions[valuesDict["system"]].values()
            ]
        except KeyError:
            partitions = []
        self.logger.debug(f"get_partition_list: partitions = {partitions}")
        return partitions

    def get_device_list(self, filter="", valuesDict=None, typeId="", targetId=0):
        self.logger.threaddebug(f"get_device_list: typeId = {typeId}, targetId = {targetId}, filter = {filter}, valuesDict = {valuesDict}")
        try:
            devices = [
                (device.id_, device.name)
                for device in self.known_sensors[valuesDict["system"]][valuesDict["partition"]].values()
            ]
        except KeyError:
            devices = []
        self.logger.debug(f"get_device_list: devices = {devices}")
        return devices

    # doesn't do anything, just needed to force other menus to dynamically refresh
    def menuChanged(self, valuesDict=None, typeId=None, devId=None):  # noqa
        self.logger.threaddebug(f"menuChanged: typeId = {typeId}, devId = {devId}, valuesDict = {valuesDict}")
        return valuesDict

    ########################################
    # Menu and Action methods
    ########################################
    def homekit_set_mode(self, action, device, callerWaitingForResult):
        self.logger.threaddebug(f"homekit_set_mode: action = {action}, device = {device.name}, callerWaitingForResult = {callerWaitingForResult}")
        mode = int(action.props.get("mode", -1))
        if mode == 0:
            mode = "home"
        elif mode == 1:
            mode = "away"
        elif mode == 2:
            mode = "night"
        elif mode == 3:
            mode = "off"
        elif mode == 4:
            self.logger.error(f"homekit_set_mode: Unable to set mode to 'triggered'")
            return
        else:
            self.logger.error(f"homekit_set_mode: Invalid mode '{mode}'")
            return

        force_bypass = action.props.get("force_bypass", False)
        no_entry_delay = action.props.get("no_entry_delay", False)
        silent_arming = action.props.get("silent_arming", False)

        part = self.known_partitions[device.pluginProps['system']][device.address]
        self.event_loop.create_task(self.async_set_mode(part, mode, force_bypass, no_entry_delay, silent_arming))

    def action_set_mode(self, action, device, callerWaitingForResult):
        self.logger.threaddebug(f"action_set_mode: action = {action}, device = {device.name}, callerWaitingForResult = {callerWaitingForResult}")
        mode = action.props.get("mode", None)
        if mode not in ['away', 'home', 'off', 'night']:
            self.logger.error(f"action_set_mode: Invalid mode '{mode}'")
            return

        force_bypass = action.props.get("force_bypass", False)
        no_entry_delay = action.props.get("no_entry_delay", False)
        silent_arming = action.props.get("silent_arming", False)

        part = self.known_partitions[device.pluginProps['system']][device.address]
        self.event_loop.create_task(self.async_set_mode(part, mode, force_bypass, no_entry_delay, silent_arming))

    async def async_set_mode(self, part, mode, force_bypass, no_entry_delay, silent_arming):
        if mode == 'off':
            await part.async_disarm(force_bypass=force_bypass, no_entry_delay=no_entry_delay, silent_arming=silent_arming)
        elif mode == 'away':
            await part.async_arm_away(force_bypass=force_bypass, no_entry_delay=no_entry_delay, silent_arming=silent_arming)
        elif mode == 'home':
            await part.async_arm_stay(force_bypass=force_bypass, no_entry_delay=no_entry_delay, silent_arming=silent_arming)
        elif mode == 'night':
            await part.async_arm_night(force_bypass=force_bypass, no_entry_delay=no_entry_delay, silent_arming=silent_arming)
        else:
            self.logger.error(f"async_set_mode: Invalid mode '{mode}'")

    ########################################
    # Recurring tasks
    ########################################

    async def async_system_refresh_loop(self) -> None:
        self.logger.debug("async_system_refresh_loop: starting")
        try:
            while True:
                await self.async_system_refresh()
                self.logger.debug(f"async_system_refresh_loop: starting timer for {self.updateFrequency} seconds")
                await asyncio.sleep(self.updateFrequency)

        except asyncio.CancelledError:
            self.logger.debug("async_system_refresh_loop: cancelled")
            raise

    # update from the alarm.com servers
    async def async_system_refresh(self) -> None:
        await self.alarm.async_update()
        self.logger.threaddebug(f"Systems ({len(self.alarm.systems)})")
        for device in self.alarm.systems:
            self.logger.threaddebug(f"Name: {device.name}, id_: {device.id_}, unit_id: {device.unit_id}")
            self.known_systems[str(device.id_)] = device
            self.known_partitions[str(device.id_)] = {}
            self.known_sensors[str(device.id_)] = {}

        self.logger.threaddebug(f"Partitions ({len(self.alarm.partitions)})")
        for device in self.alarm.partitions:
            try:
                self.logger.threaddebug(f"Name: {device.name} ({device.id_}), State: {device.state}, System: {device.system_id}")
                self.known_partitions[str(device.system_id)][str(device.id_)] = device
                self.known_sensors[str(device.system_id)][str(device.id_)] = {}
            except KeyError as err:
                self.logger.error(f"async_system_refresh: {err}")

        self.logger.threaddebug(f"Sensors ({len(self.alarm.sensors)})")
        for device in self.alarm.sensors:
            self.logger.threaddebug(f"Name: {device.name} ({device.id_}), State: {device.state}, System: {device.system_id}, Partition: {device.partition_id}")
            self.known_sensors[str(device.system_id)][str(device.partition_id)][str(device.id_)] = device

        self.logger.threaddebug(f"known_systems: {self.known_systems}")
        self.logger.threaddebug(f"known_partitions: {self.known_partitions}")
        self.logger.threaddebug(f"known_sensors: {self.known_sensors}")

        await self.async_device_refresh()

    # update the indigo devices
    async def async_device_refresh(self) -> None:

        self.logger.threaddebug(f"active_systems: {self.active_systems}")
        for device_id in self.active_systems:
            self.update_system_device(indigo.devices[device_id])

        self.logger.threaddebug(f"active_partitions:   {self.active_partitions}")
        for device_id in self.active_partitions:
            self.update_partition_device(indigo.devices[device_id])

        self.logger.threaddebug(f"active_sensors: {self.active_sensors}")
        for device_id in self.active_sensors:
            self.update_sensor_device(indigo.devices[device_id])

    def update_system_device(self, device):
        try:
            system = self.known_systems[device.address]
        except KeyError:
            return
        self.logger.debug(f"{device.name}: update_system_device for {system.name}")
        if system.battery_critical:
            battery = "Critical"
        elif system.battery_low:
            battery = "Low"
        else:
            battery = "Normal"
        update_list = [
            {'key': "name", 'value': system.name},
            {'key': "battery", 'value': battery},
            {'key': "malfunction", 'value': system.malfunction},
        ]
        try:
            device.updateStatesOnServer(update_list)
        except Exception as e:
            self.logger.error(f"{device.name}: failed to update states: {e}")

    def update_partition_device(self, device):
        try:
            partition = self.known_partitions[device.pluginProps["system"]][device.address]
        except KeyError:
            return
        self.logger.debug(f"{device.name}: update_partition_device for {partition.name}")
        if partition.battery_critical:
            battery = "Critical"
        elif partition.battery_low:
            battery = "Low"
        else:
            battery = "Normal"
        update_list = [
            {'key': "name", 'value': partition.name},
            {'key': "battery", 'value': battery},
            {'key': "malfunction", 'value': partition.malfunction},
            {'key': "uncleared_issues", 'value': partition.uncleared_issues},
            {'key': "state", 'value': str(partition.state)},
        ]
        try:
            device.updateStatesOnServer(update_list)
        except Exception as e:
            self.logger.error(f"{device.name}: failed to update states: {e}")

    def update_sensor_device(self, device):
        try:
            sensor = self.known_sensors[device.pluginProps["system"]][device.pluginProps["partition"]][device.address]
        except KeyError:
            return
        self.logger.debug(f"{device.name}: update_sensor_device for {sensor.name}")
        if sensor.battery_critical:
            battery = "Critical"
        elif sensor.battery_low:
            battery = "Low"
        else:
            battery = "Normal"
        update_list = [
            {'key': "name", 'value': sensor.name},
            {'key': "battery", 'value': battery},
            {'key': "malfunction", 'value': sensor.malfunction},
            {'key': "model_text", 'value': sensor.model_text},
            {'key': "state", 'value': str(sensor.state)},
        ]
        try:
            device.updateStatesOnServer(update_list)
        except Exception as e:
            self.logger.error(f"{device.name}: failed to update states: {e}")
