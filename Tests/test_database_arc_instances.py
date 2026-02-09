# -*- coding: utf-8 -*-

from Lib.database_arc_oem import DatabaseArcFromOEM


class DatabaseArcFromOEM_Test(DatabaseArcFromOEM):
    def __init__(self, oem_conn):
        DatabaseArcFromOEM.__init__(self, oem_conn)


    def _resolve_database(self, identity):
        return {
            "db_name": "APPDB",
            "db_unique_name": "APPDB_PRD",
            "role": "PRIMARY"
        }

    def _populate_instances(self, db_info):
        # Mock instances
        self.arc.add_instance(
            instance_name="APPDB1",
            host="srv1",
            cname="srv1-db",
            version="19.23.0.0.0"
        )
        self.arc.add_instance(
            instance_name="APPDB2",
            host="srv2",
            cname="srv2-db",
            version="19.23.0.0.0"
        )

    def _populate_rac(self, db_info):
        pass

    def _populate_services(self, db_info):
        pass

    def _populate_dataguard(self, db_info):
        pass


def test_instances_population():
    arc = DatabaseArcFromOEM_Test(oem_conn=None)
    db_arc = arc.build_from_identifier("ANY")

    instances = db_arc.to_dict()["Database"]["instances"]

    assert len(instances) == 2
    assert instances[0]["instance_name"] == "APPDB1"
    assert instances[1]["host"] == "srv2"

    print "OK: instances populated correctly"


if __name__ == "__main__":
    test_instances_population()
