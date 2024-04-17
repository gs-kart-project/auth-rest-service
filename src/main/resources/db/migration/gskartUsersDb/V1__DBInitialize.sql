use gskartUsers;

-- Drop FK_UserRoles_RoleId
set @fkExists = (select 1 from information_schema.table_constraints where table_schema = DATABASE() and table_name = 'users_roles' and constraint_name = 'FK_UserRoles_RoleId' and constraint_type = 'FOREIGN KEY');
set @DropFkQuery = if (@fkExists > 0, 'alter table users_roles drop foreign key FK_UserRoles_RoleId', 'select ''Foreign key does not exist''');
PREPARE stmt FROM @DropFkQuery;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Drop FK_UserRoles_UserId
set @fkExists = (select 1 from information_schema.table_constraints where table_schema = DATABASE() and table_name = 'users_roles' and constraint_name = 'FK_UserRoles_UserId' and constraint_type = 'FOREIGN KEY');
set @DropFkQuery = if (@fkExists > 0, 'alter table users_roles drop foreign key FK_UserRoles_UserId', 'select ''Foreign key does not exist''');
PREPARE stmt FROM @DropFkQuery;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

drop table if exists roles;
drop table if exists users;
drop table if exists users_roles;

create table roles (
                       created_on datetime(6), id bigint not null auto_increment, modified_on datetime(6), created_by varchar(255), description varchar(255),
                       modified_by varchar(255), name varchar(255), primary key (id)) engine=InnoDB;

create table users (
                       created_on datetime(6), id bigint not null auto_increment, modified_on datetime(6), created_by varchar(255), email varchar(255), firstname varchar(255),
                       lastname varchar(255), modified_by varchar(255), password varchar(255), username varchar(255), primary key (id)) engine=InnoDB;

create table users_roles (roles_id bigint not null, users_id bigint not null, primary key (roles_id, users_id)) engine=InnoDB;

alter table users_roles add constraint FK_UserRoles_RoleId foreign key (roles_id) references roles (id);

alter table users_roles add constraint FK_UserRoles_UserId foreign key (users_id) references users (id);