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
