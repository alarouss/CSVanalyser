from Lib.database_arc import DatabaseArchitecture

arc = DatabaseArchitecture()
arc.set_database_identity("APPDB", "APPDB_PRD", "PRIMARY")
arc.set_rac(True, "appdb-scan.company.fr")

arc.add_instance("APPDB1", "srv1", cname="srv1-db", version="19.23.0.0.0")
arc.add_instance("APPDB2", "srv2", cname="srv2-db", version="19.23.0.0.0")

print arc.to_dict()
