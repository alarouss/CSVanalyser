# -*- coding: utf-8 -*-

from Lib.host_coherence import check_host_coherence

def test_host_coherence_seq_from_database():
    """
    Database : M19ACCP0  -> SEQ = P0
    Application : ACCUEIL-CLIENT
    Attendu :
      - ACCUEIL-CLIENTP0DB.<dns>
      - ACCUEIL-CLIENTP0DR.<dns>
    """

    raw = {
        "Databases": "M19ACCP0"
    }

    net_new = {
        "Primaire": {
            "host": "ACCUEIL-CLIENTP0DB.GROUPE.GENERALI.FR"
        },
        "DR": {
            "host": "ACCUEIL-CLIENTP0DR.GROUPE.GENERALI.FR"
        }
    }

    coh = check_host_coherence(
        application="ACCUEIL-CLIENT",
        new_network_block=net_new,
        rawsource=raw
    )

    assert coh["PrimaryOK"] is True
    assert coh["DROK"] is True
    assert coh["GlobalOK"] is True

    print("OK — sequence extracted from database and applied correctly")


if __name__ == "__main__":
    test_host_coherence_seq_from_database()
