CREATE USER spot_on_user PASSWORD 'spot_on_user';

DO $$
BEGIN
	FOR i IN 1..26 LOOP
	    FOR j IN 1..26 LOOP
	    	EXECUTE('CREATE TABLE IF NOT EXISTS spot_on_urls_' ||
			CHR(i + 96) || CHR(j + 96) ||
	    		'(
			date_time_inserted TEXT NOT NULL,
			description BYTEA,
			title BYTEA NOT NULL,
			url BYTEA NOT NULL,
			url_hash TEXT PRIMARY KEY NOT NULL)'
		       );
	    END LOOP;
	END LOOP;
END;
$$;
