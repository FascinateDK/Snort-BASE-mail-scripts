<?php

// Database informations
define("CONST_DB_TYPE","mysql");
define("CONST_DB_NAME","snort");
define("CONST_DB_USER","snort");
define("CONST_DB_PWD","password");

// File configuration
define("CONST_FILE_PATH","/var/log/apache2/");
define("CONST_FILE_NAME","mailAnalyse.csv");

// Mail sender configuration

define("CONST_MAIL_SENDER_NAME","Snort Alert");
define("CONST_MAIL_SENDER_ADDRESS","Snort@alert.com");
define("CONST_MAIL_RECIPIENT_ADDRESS","your@email");

// CSV link configuration

define("CONST_SERVER_IP", "localhost");

// Alert configuration

define("CONST_SUBJECT_EMERGENCY", 5);
define("CONST_SUBJECT_FATAL_EMERGENCY", 20);
define("CONST_SUBJECT_WARNING", 10);
?>
