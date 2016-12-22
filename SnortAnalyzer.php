#!/usr/bin/php

<?php
include 'include/functions.php';
include 'include/constants.php';

/***************************************************************************************************************
** Script which send mail with hourly Snort statistics based on Basic Analysis and Security Engine's database  *
**  																										                                                       *
** Script actions : 																						                                               *
**  - take signature, description, number of alerts, number of ip_src, ip_dst, first & last alert timestamp AND*
**    hyperlink to the GUI.
**  - Generate csv file with all mentionned details 														                               *
**  - Send mail with short description of the hourly analyse with detailed csv file as attachment 			       *
****************************************************************************************************************
** Authors: 																								                                                   *
****************************************************************************************************************
** Donovan Kozak <donovan.kozak@yahoo.fr 																	                                     *
***************************************************************************************************************/

$actualTime = date("Y-m-d H:i:s");
$lastCheck = last_Time_Check();
//$lastCheck = '2016-12-01 10:00:00'; // TEST VARIABLE REMOVE FOR PROD VERSION

$db = db_Connect(CONST_DB_TYPE, CONST_DB_NAME, CONST_DB_USER, CONST_DB_PWD);

if($db)
{
	$totalAlerts = 0;
	$priority = array(0,0,0);
	$Headers = array("Sig","Sig. description","Priority", "Alert SUM", "ip_src SUM", "ip_dst SUM", "First alert", "Last alert", "Link");

	$signatures = request_Get_Signature($db, $lastCheck, $actualTime);

	$fp = fopen(CONST_FILE_PATH.CONST_FILE_NAME, 'w');
	fputcsv($fp, $Headers);

	for($i = 0; $i != count($signatures); $i++)
	{
		$nb_Same_Sig = request_Get_Nb_Same_Sig($db, $signatures[$i][0], $lastCheck, $actualTime);
		$list_IP_SRC = request_Get_IP_SRC($db, $signatures[$i][0], $lastCheck, $actualTime);
		$list_IP_DST = request_Get_IP_DST($db, $signatures[$i][0], $lastCheck, $actualTime);
		$list_timestamp = request_Get_Timestamp($db, $signatures[$i][0], $lastCheck, $actualTime);
		$lastAlert = $list_timestamp[0][0];
		$firstAlert = $list_timestamp[count($list_timestamp)-1][0];
		$link = construct_Link($signatures[$i][0]);

		$csvInsert = array($signatures[$i][0], $signatures[$i][1], $signatures[$i][2], $nb_Same_Sig[0], count($list_IP_SRC), count($list_IP_DST), $firstAlert, $lastAlert, $link);
		$totalAlerts = $totalAlerts + $nb_Same_Sig[0];

    if($signatures[$i][2] == 1)
    {
      $priority[0] = $priority[0] + 1;
    }
    else if($signatures[$i][2] == 2)
    {
      $priority[1] = $priority[1] + 1;
    }
    else
    {
      $priority[2] = $priority[2] + 1;
    }

		fputcsv($fp, $csvInsert);
	}
	fclose($fp);

	if($totalAlerts > 1)
	{
		send_Mail(CONST_FILE_PATH, CONST_FILE_NAME, CONST_MAIL_SENDER_NAME, CONST_MAIL_SENDER_ADDRESS, CONST_MAIL_RECIPIENT_ADDRESS, $lastCheck, $actualTime, $totalAlerts, $signatures, $priority[0], $priority[1], $priority[2]);
	}
	$db = null;
}

?>
