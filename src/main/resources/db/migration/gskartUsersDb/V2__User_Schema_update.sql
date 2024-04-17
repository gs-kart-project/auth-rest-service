alter table users add column credentials_status tinyint check (credentials_status between 0 and 1);
alter table users add column user_status tinyint check (user_status between 0 and 3);