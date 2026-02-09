# -*- coding: utf-8 -*-
# Lib/database_arc.py
#
# Database architecture canonical model
# Contract JSON v1.x locked
#
# This module is intentionally passive:
# - no OEM access
# - no DGMGRL access
# - no CLI
# It only builds and exposes the canonical Database architecture structure.

class DatabaseArchitecture(object):

    def __init__(self):
        # Canonical JSON structure (locked contract)
        self._data = {
            "Database": {
                "db_name": None,
                "db_unique_name": None,
                "role": None,              # PRIMARY / PHYSICAL STANDBY / LOGICAL STANDBY / ...
                "is_rac": None,

                "scan": None,              # dict if RAC, else None

                "instances": [],           # list of instances
                "services": [],            # list of services with per-instance state

                "dataguard": {
                    "has_standby": False,
                    "standby": []
                }
            }
        }

    # ------------------------------------------------------------------
    # Database identity
    # ------------------------------------------------------------------

    def set_database_identity(self, db_name, db_unique_name, role):
        self._data["Database"]["db_name"] = db_name
        self._data["Database"]["db_unique_name"] = db_unique_name
        self._data["Database"]["role"] = role

    # ------------------------------------------------------------------
    # RAC / SCAN
    # ------------------------------------------------------------------

    def set_rac(self, is_rac, scan_name=None, scan_port=1521):
        self._data["Database"]["is_rac"] = bool(is_rac)
        if is_rac:
            self._data["Database"]["scan"] = {
                "name": scan_name,
                "port": scan_port
            }
        else:
            self._data["Database"]["scan"] = None

    # ------------------------------------------------------------------
    # Instances
    # ------------------------------------------------------------------

    def add_instance(self, instance_name, host, cname=None, version=None):
        self._data["Database"]["instances"].append({
            "instance_name": instance_name,
            "host": host,
            "cname": cname,
            "version": version
        })

    # ------------------------------------------------------------------
    # Services
    # ------------------------------------------------------------------

    def add_service(self, service_name, policy, role):
        service = {
            "service_name": service_name,
            "policy": policy,   # AUTOMATIC / MANUAL
            "role": role,       # PRIMARY / STANDBY / BOTH
            "instances": []
        }
        self._data["Database"]["services"].append(service)
        return service

    def add_service_instance_state(self, service, instance_name, state, preferred=None):
        entry = {
            "instance_name": instance_name,
            "state": state     # RUNNING / STOPPED
        }
        if preferred is not None:
            entry["preferred"] = bool(preferred)
        service["instances"].append(entry)

    # ------------------------------------------------------------------
    # Data Guard
    # ------------------------------------------------------------------

    def enable_dataguard(self):
        self._data["Database"]["dataguard"]["has_standby"] = True

    def add_standby_database(self, standby_database_dict):
        # standby_database_dict must itself respect the Database contract
        self._data["Database"]["dataguard"]["has_standby"] = True
        self._data["Database"]["dataguard"]["standby"].append(
            standby_database_dict
        )

    # ------------------------------------------------------------------
    # Output
    # ------------------------------------------------------------------

    def to_dict(self):
        # Return a deep-ish copy protection is intentionally NOT enforced:
        # caller is responsible for not mutating the structure incorrectly.
        return self._data
