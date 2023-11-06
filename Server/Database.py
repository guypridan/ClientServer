import sqlite3
import threading
from datetime import datetime

"""
Author: Guy Pridan
Purpose: This Python script is intended for accessing an SQLite database in a thread-safe manner. 
SQLite is a lightweight, serverless, and self-contained SQL database engine.
This script contains functions and logic for interacting with the SQLite database while ensuring concurrent thread safety.

NOTE: SQLite is a problematic choice for multi-thread database.
but this is an assignment for a university project.
Using SQLite were part of the instructions.
to overcome SQLite disadvantages working with multiple threads I used the threading lib and a mutex solution
"""


class DB:

    def __init__(self):
        self.db_path = "defensive.db"
        db = sqlite3.connect(self.db_path)
        operator = db.cursor()

        # create clients table
        operator.execute('''CREATE TABLE IF NOT EXISTS clients (
                                id BLOB PRIMARY KEY,
                                name TEXT,
                                publicKey BLOB,
                                lastSeen DATETIME,
                                AESkey BLOB
                                )''')

        # create files table
        operator.execute('''CREATE TABLE IF NOT EXISTS files (
                                id BLOB,
                                fileName TEXT,
                                path TEXT,
                                verified INTEGER,
                                PRIMARY KEY(id,fileName))''')
        db.close()

        # initialize mutex for thread safety
        self.mutex = threading.Lock()

        # load database to ram as requested in assignment details
        self._clients = self.get_clients()
        self._files = self.get_files()

    def get_table(self, table, condition="", condition_variables=None) -> dict:

        # execute query
        rows = self.thread_safe_execute(f"SELECT * FROM {table} {condition}", condition_variables, True)
        column_names = self.get_col_names(table)
        data = {}
        for row in rows:
            key = row[0]
            data[key] = {
                col: val for col, val in zip(column_names[1:], row[1:])
            }

        return data

    def get_clients(self) -> dict:

        # execute query
        rows = self.thread_safe_execute(f"SELECT * FROM clients", ret_flag=True)

        # unpack table into python dict
        column_names = self.get_col_names('clients')
        data = {}
        for row in rows:
            key = row[0]
            data[key] = {
                col: val for col, val in zip(column_names[1:], row[1:])
            }

        return data

    def get_files(self):

        # execute query
        rows = self.thread_safe_execute(f"SELECT * FROM files", ret_flag=True)

        # unpack table into python dict
        column_names = self.get_col_names("files")
        data = {}
        for row in rows:
            if row[0] not in data:
                data[row[0]] = {}
            data[row[0]][row[1]] = {
                col: val for col, val in zip(column_names[2:], row[2:])
            }
        return data

    def get_col_names(self, table) -> list[str]:
        cols_info = self.thread_safe_execute(f"PRAGMA table_info({table})", ret_flag=True)
        return [col_info[1] for col_info in cols_info]

    def get_keys(self, cid: bytes) -> tuple[bytes, bytes]:
        rsa_data, aes_key = self.thread_safe_execute("SELECT publicKey, AESkey FROM clients WHERE id=?",
                                                     (cid,), True)[0]
        return rsa_data, aes_key

    def get_rsa(self, cid: bytes) -> bytes:
        rsa, = self.thread_safe_execute("SELECT publicKey FROM clients WHERE id=?",
                                        (cid,), True)[0]
        return rsa

    def get_aes(self, cid: bytes) -> bytes:
        aes, = self.thread_safe_execute("SELECT AESkey FROM clients WHERE id=?",
                                        (cid,), True)[0]
        return aes

    def add_client(self, cid: bytes, name: str):

        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self._clients[cid] = {"name": name,
                              "publicKey": None,
                              "lastSeen": now,
                              "AESkey": None}

        self.thread_safe_execute("INSERT INTO clients(id,name,publicKey,lastSeen,AESkey) VALUES(?,?,?,?,?)",
                                 (cid,
                                  name,
                                  None,
                                  now,
                                  None))

    def update_last_seen(self, cid: bytes) -> None:
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self._clients[cid]["lastSeen"] = now
        self.thread_safe_execute("UPDATE clients SET lastSeen = ? WHERE id = ?",
                                 (now, cid))

    def insert_cript_keys(self, cid: bytes, rsa_data: bytes, aes_key: bytes) -> None:

        blob_rsa = sqlite3.Binary(rsa_data)
        blob_aes = sqlite3.Binary(aes_key)

        self._clients[cid]["publicKey"] = blob_rsa
        self._clients[cid]["AESkey"] = blob_aes

        self.thread_safe_execute("UPDATE clients SET publicKey=?, AESkey=? WHERE id=?",
                                 (blob_rsa, blob_aes, cid))

    def insert_aes(self, cid: bytes, aes_key: bytes) -> None:
        blob_aes = sqlite3.Binary(aes_key)
        self._clients[cid]["AESkey"] = blob_aes
        self.thread_safe_execute("UPDATE clients SET AESkey=? WHERE id=?",
                                 (blob_aes, cid))

    def add_file(self, cid: bytes, f_name: str, f_path: str) -> None:

        file_exists = self.thread_safe_execute("SELECT * FROM files WHERE id=? AND fileName=?",
                                          (cid, f_name), True)

        if file_exists:
            self._files[cid][f_name]["verified"] = False
            self.thread_safe_execute("UPDATE files SET verified=? WHERE id=? and fileName=?",
                                     (False, cid, f_name))
        else:
            if cid not in self._files:
                self._files[cid] = {}
            self._files[cid][f_name] = {"path": f_path, "verified": False}
            self.thread_safe_execute("INSERT INTO files(id,fileName,path,verified) VALUES(?,?,?,?)",
                                     (cid, f_name, f_path, False))
        self.update_last_seen(cid)

    def verify_file(self, cid: bytes, f_name: str) -> None:
        self.thread_safe_execute("UPDATE files SET verified=? WHERE id=? AND fileName=?",
                                 (True, cid, f_name))

    def remove_file(self, cid: bytes, f_name: str) -> None:
        del self._files[cid][f_name]
        self.thread_safe_execute("DELETE FROM files WHERE id=? AND fileName=?",
                                 (cid, f_name))

    def thread_safe_execute(self, query: str, params=(), ret_flag=False) -> list | None:
        self.mutex.acquire()
        db = sqlite3.connect(self.db_path)
        operator = db.cursor()

        try:
            if params:
                operator.execute(query, params)
            else:
                operator.execute(query)

            if ret_flag:
                ret = operator.fetchall()
            else:
                db.commit()

        except sqlite3.Error as e:
            print("SQLite error:", e)
            ret_flag = False

        finally:
            db.close()
            self.mutex.release()
            return ret if ret_flag else None


