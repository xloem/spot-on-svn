/*
** Before executing this script, please create the spoton database:
** create database spoton;
*/

CREATE USER spoton PASSWORD 'spoton';

CREATE TABLE papyrus_account
(
	id		  TEXT NOT NULL UNIQUE,
	is_local	  INTEGER NOT NULL DEFAULT 0,
	passphrase_salt	  TEXT,
	passphrase_salted TEXT
);

CREATE TABLE papyrus_idiotes
(
	papyrus_account_id	 TEXT NOT NULL,
	key_id                   TEXT NOT NULL,
	private_key		 TEXT,
	public_key		 TEXT NOT NULL,
	PRIMARY KEY(papyrus_account_id, key_id),
	FOREIGN KEY(papyrus_account_id) REFERENCES papyrus_account(id) ON DELETE CASCADE
);

GRANT DELETE, INSERT, SELECT, UPDATE ON papyrus_account TO spoton;
GRANT DELETE, INSERT, SELECT, UPDATE ON papyrus_idiotes TO spoton;
