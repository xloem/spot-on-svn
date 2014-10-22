DROP DATABASE IF EXISTS spot_on_user_db;

DO $$
BEGIN
	FOR i IN 1..26 LOOP
	    FOR j IN 1..26 LOOP
		EXECUTE('DROP TABLE IF EXISTS spot_on_keywords_' ||
                        CHR(i + 96) || CHR(j + 96)
                       );
	    	EXECUTE('DROP TABLE IF EXISTS spot_on_urls_' ||
			CHR(i + 96) || CHR(j + 96)
	    	       );
	    END LOOP;
	END LOOP;
END;
$$;

DROP USER IF EXISTS spot_on_user;
