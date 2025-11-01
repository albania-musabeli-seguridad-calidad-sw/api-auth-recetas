--create database securitydbjwt;
--create user 'myuser'@'%' identified by 'password';
--grant all on securitydbjwt.* to 'myuser'@'%';

-- create.sql
CREATE DATABASE IF NOT EXISTS `${MYSQL_DATABASE}`;

CREATE USER IF NOT EXISTS '${MYSQL_USER}'@'%' IDENTIFIED BY '${MYSQL_PASSWORD}';

GRANT ALL PRIVILEGES ON `${MYSQL_DATABASE}`.* TO '${MYSQL_USER}'@'%';

--FLUSH PRIVILEGES;