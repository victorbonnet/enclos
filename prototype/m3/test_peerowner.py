"""Tests of peerowner.py and the listener's refusal on fixture socket tables:
the client's row decides, and anything else is refused. Pure, so it runs
anywhere:

    python3 -I prototype/m3/test_peerowner.py
"""

import importlib.util
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import peerowner  # noqa: E402

HEAD = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
ME, OTHER = 1001, 1002
SERVER = ("127.0.0.1", 18931)
CLIENT = ("127.0.0.1", 40000)  # 0x9C40; 18931 is 0x49F3


def row(local, remote, state, uid):
    return f"   0: {local} {remote} {state} 00000000:00000000 00:00000000 00000000 {uid:5} 0 123 1\n"


LOOP = "0100007F"
LISTEN = row(f"{LOOP}:49F3", "00000000:0000", "0A", ME)
ACCEPTED = row(f"{LOOP}:49F3", f"{LOOP}:9C40", "01", ME)


def table(*lines):
    return HEAD + "".join(lines)


def client(uid, state="01"):
    return row(f"{LOOP}:9C40", f"{LOOP}:49F3", state, uid)


MAPPED_LOOP = "0000000000000000FFFF00000100007F"


class Owner(unittest.TestCase):
    def test_the_client_row_decides_not_the_accepted_one(self):
        tables = [table(LISTEN, ACCEPTED, client(OTHER))]
        self.assertEqual(peerowner.owner(tables, CLIENT, SERVER), OTHER)

    def test_a_dual_stack_client_is_found_in_tcp6(self):
        six = table(row(f"{MAPPED_LOOP}:9C40", f"{MAPPED_LOOP}:49F3", "01", ME))
        self.assertEqual(peerowner.owner([table(LISTEN, ACCEPTED), six], CLIENT, SERVER), ME)

    def test_a_client_gone_is_unknown(self):
        self.assertIsNone(peerowner.owner([table(LISTEN, ACCEPTED)], CLIENT, SERVER))

    def test_a_row_not_established_is_unknown(self):
        for state in ("06", "04", "05", "08"):  # TIME_WAIT reads uid 0
            self.assertIsNone(peerowner.owner([table(client(0, state))], CLIENT, SERVER), state)

    def test_two_owners_are_unknown(self):
        self.assertIsNone(peerowner.owner([table(client(ME), client(OTHER))], CLIENT, SERVER))

    def test_another_port_or_address_does_not_match(self):
        self.assertIsNone(peerowner.owner([table(client(ME))], ("127.0.0.1", 40001), SERVER))
        self.assertIsNone(peerowner.owner([table(client(ME))], ("127.0.0.2", 40000), SERVER))

    def test_no_table_and_a_malformed_row_are_unknown(self):
        self.assertIsNone(peerowner.owner([], CLIENT, SERVER))
        self.assertIsNone(peerowner.owner([HEAD + "   0: nonsense\n"], CLIENT, SERVER))

    def test_only_the_expected_uid_is_allowed(self):
        self.assertTrue(peerowner.allowed(ME, ME))
        self.assertFalse(peerowner.allowed(OTHER, ME))
        self.assertFalse(peerowner.allowed(0, ME))
        self.assertFalse(peerowner.allowed(None, ME))

    def test_an_unreadable_table_is_left_out(self):
        self.assertEqual(peerowner.read_tables(["/nonexistent/tcp"]), [])


class Conn:
    def __init__(self):
        self.closed = False

    def getpeername(self):
        return CLIENT

    def getsockname(self):
        return SERVER

    def close(self):
        self.closed = True


class Admit(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("host_listen", f"{HERE}/host-listen.py")
        self.listen = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.listen)
        self.relayed = []
        self.listen.relay.one = lambda conn, path: self.relayed.append(path)

    def admit(self, tables):
        conn = Conn()
        self.listen.admit(conn, "S", ME, read=lambda: tables, say=lambda _: None)
        return conn

    def test_the_user_reaches_the_socket(self):
        self.assertEqual(self.relayed, [])
        conn = self.admit([table(client(ME))])
        self.assertEqual(self.relayed, ["S"])
        self.assertFalse(conn.closed)

    def test_another_user_or_an_unknown_owner_is_closed_before_the_socket(self):
        for tables in ([table(client(OTHER))], [table()], []):
            conn = self.admit(tables)
            self.assertTrue(conn.closed)
            self.assertEqual(self.relayed, [])


if __name__ == "__main__":
    unittest.main()
