CREATE USER aiohttp_security WITH PASSWORD 'aiohttp_security';
DROP DATABASE IF EXISTS aiohttp_security;
CREATE DATABASE aiohttp_security;
ALTER DATABASE aiohttp_security OWNER TO aiohttp_security;
GRANT ALL PRIVILEGES ON DATABASE aiohttp_security TO aiohttp_security;

-- create users table
CREATE TABLE IF NOT EXISTS users
(
  id integer NOT NULL,
  login character varying(256) NOT NULL,
  passwd character varying(256) NOT NULL,
  is_superuser boolean NOT NULL DEFAULT false,
  disabled boolean NOT NULL DEFAULT false,
  CONSTRAINT user_pkey PRIMARY KEY (id),
  CONSTRAINT user_login_key UNIQUE (login)
);

-- and permissions for them
CREATE TABLE IF NOT EXISTS permissions
(
  id integer NOT NULL,
  user_id integer NOT NULL,
  perm_name character varying(64) NOT NULL,
  CONSTRAINT permission_pkey PRIMARY KEY (id),
  CONSTRAINT user_permission_fkey FOREIGN KEY (user_id)
      REFERENCES users (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE CASCADE
);
