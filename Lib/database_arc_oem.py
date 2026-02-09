# -*- coding: utf-8 -*-
# Lib/database_arc_oem.py
#
# OEM adapter for DatabaseArchitecture
#
# IMPORTANT:
# - no CLI
# - no side effects
# - no ReportV3 dependency
# - OEM access will be plugged later

from Lib.database_arc import DatabaseArchitecture
from Lib.oem_flow import oem_get_database_identity
from Lib.oem_flow import oem_list_instances



class DatabaseArcFromOEM(object):

    def __init__(self, oem_conn):
        self.oem_conn = oem_conn
        self.arc = DatabaseArchitecture()

    # ------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------

    def build_from_identifier(self, identifier):
        """
        Entry point.
        identifier can be:
          - instance_name
          - db_unique_name
          - db_name

        This method orchestrates the discovery.
        """
        db_info = self._resolve_database(identity=identifier)

        self.arc.set_database_identity(
            db_info.get("db_name"),
            db_info.get("db_unique_name"),
            db_info.get("role")
        )

        self._populate_instances(db_info)
        self._populate_rac(db_info)
        self._populate_services(db_info)
        self._populate_dataguard(db_info)

        return self.arc

    # ------------------------------------------------------------
    # Internal steps (stubs for now)
    # ------------------------------------------------------------

    def _resolve_database(self, identity):
        """
        Resolve identity to a database anchor.
        To be implemented with OEM.
        """
        raise NotImplementedError("_resolve_database not implemented")

    def _populate_instances(self, db_info):
        """
        Fill instances[] with:
          instance_name, host, cname, version
        """
        pass

    def _populate_rac(self, db_info):
        """
        Detect RAC and SCAN if applicable.
        """
        pass

    def _populate_services(self, db_info):
        """
        Fill services[] with per-instance state.
        """
        pass

    def _populate_dataguard(self, db_info):
        """
        Data Guard discovery.
        OEM or DGMGRL later.
        """
        pass


class DatabaseArcFromOEM(object):

    # ... (le reste inchangé)

    def _resolve_database(self, identity):
        """
        Resolve identifier to database anchor.
        Returns a dict with:
          - db_name
          - db_unique_name
          - role
        """

        info = oem_get_database_identity(self.oem_conn, identity)

        if not info:
            raise Exception("Unable to resolve database identity for '%s'" % identity)

        # Expected minimal contract from oem_flow
        db_name = info.get("db_name")
        db_unique_name = info.get("db_unique_name")
        role = info.get("role")

        if not db_unique_name:
            raise Exception("OEM resolution missing db_unique_name for '%s'" % identity)

        return {
            "db_name": db_name,
            "db_unique_name": db_unique_name,
            "role": role
        }
    def _populate_instances(self, db_info):
        """
        Populate instances[]:
          - instance_name
          - host
          - cname
          - version
        """
        db_unique_name = db_info.get("db_unique_name")

        instances = oem_list_instances(self.oem_conn, db_unique_name)
        if not instances:
            return

        for inst in instances:
            self.arc.add_instance(
                instance_name=inst.get("instance_name"),
                host=inst.get("host"),
                cname=inst.get("cname"),
                version=inst.get("version")
            )
