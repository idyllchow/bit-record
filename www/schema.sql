-- schema.sql

drop database if exists bitrecord;

create database bitrecord;

use bitrecord; 


grant select, insert, update, delete on bitrecord.* to 'shibo'@'localhost' identified by '111111';


create table users (
	      `id` varchar(50) not null,
	      `email` varchar(50) not null,
	      `passwd` varchar(50) not null,
	      `admin` bool not null,
	      `name` varchar(50) not null,
	      `image` varchar(500) not null,
	      `created_at` real not null,
	      unique key `idx_email` (`email`),
	      key `idx_created_at` (`created_at`),
	      primary key (`id`)
	  ) engine=innodb default charset=utf8;
 
create table interfaces (
              `id` varchar(50) not null,
              `interface_id` varchar(50) not null,
              `interface_name` varchar(50) not null,
              `interface_image` varchar(500) not null,
              `name` varchar(50) not null,
              `summary` varchar(200) not null,
    	      `content` mediumtext not null,
	      `created_at` real not null,
              key `idx_created_at` (`created_at`),
              primary key (`id`)
) engine=innodb default charset=utf8;
