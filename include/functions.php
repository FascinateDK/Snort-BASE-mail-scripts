<?php

function db_Connect($dbtype, $dbName, $user, $password, $host = 'localhost')
{
    try
    {
      $db = new PDO("$dbtype:host=$host;dbname=$dbName", "$user", "$password");

      return $db;
    }
    catch(PDOException $e)
    {
      $db = null;
      echo 'ERROR DB: ' . $e->getMessage();
    }
}

function last_Time_Check($year = 0, $month = 0, $day = 0, $hour = 1, $minute = 0, $second = 0){
  if(date("m")-$month >= 1 && date("d")-$day >= 1 && date("H")-$hour >= -1 && date("i")-$minute >= 0 && date("s")-$second >= 0)
  {
    $years = date("Y")-$year;
    $months = date("m")-$month;
    $days = date("d")-$day;

    $date = $years . "-" . $months . "-" . $days;

    $hours = date("H")-$hour;
    $minutes = date("i")-$minute;
    $seconds = date("s")-$second;

    $time = $hours . ":" . $minutes . ":" . $seconds;

    $lastCheck = $date . ' ' . $time;

    return $lastCheck;
  }
  else
  {
    echo "ERROR : Bad timestamp, check your function's parameters";
  }

}

function request_Get_Signature($db, $lastCheck, $actualTime)
{
  $request = $db->query("SELECT DISTINCT signature, sig_name, sig_priority
               FROM acid_event
               WHERE timestamp
               BETWEEN '". $lastCheck ."' AND '". $actualTime ."'");

  $signature = $request->fetchAll();

  return $signature;
}

function request_Get_Nb_Same_Sig($db, $signature, $lastCheck, $actualTime)
{
  $request = $db->query("SELECT count(*)
               FROM acid_event
               WHERE signature = '". $signature ."' AND timestamp BETWEEN '". $lastCheck ."' AND '".$actualTime ."'");

  $nb_Same_Sig = $request->fetch();

  return $nb_Same_Sig;
}

function request_Get_IP_SRC($db, $signature, $lastCheck, $actualTime)
{
  $request = $db->query("SELECT DISTINCT ip_src
               FROM  `acid_event`
               WHERE signature = '". $signature ."' AND TIMESTAMP BETWEEN '". $lastCheck ."' AND '". $actualTime ."'");

  $list_IP_SRC = $request->fetchAll();

  return $list_IP_SRC;
}

function request_Get_IP_DST($db, $signature, $lastCheck, $actualTime)
{
  $request = $db->query("SELECT DISTINCT ip_dst
               FROM  `acid_event`
               WHERE signature = '". $signature ."' AND TIMESTAMP BETWEEN '". $lastCheck ."' AND '". $actualTime ."'");

  $list_IP_DST = $request->fetchAll();

  return $list_IP_DST;
}

function request_Get_Timestamp($db, $signature, $lastCheck, $actualTime)
{
  $request = $db->query("SELECT timestamp
               FROM  `acid_event`
               WHERE signature = '". $signature ."' AND TIMESTAMP BETWEEN '". $lastCheck ."' AND '". $actualTime ."'
               ORDER BY timestamp DESC");

  $list_timestamp = $request->fetchAll();

  return $list_timestamp;
}

function send_Mail($path, $filename, $fromName, $fromMail, $mailTo, $lastCheck, $actualTime, $totalAlerts, $signatures, $priority_one, $priority_two, $priority_three)
{
  if($priority_one >= CONST_SUBJECT_EMERGENCY)
  {
    $subject = "emergency ! Alert from " . $lastCheck . " - " . $actualTime;
  }
  else if($priority_one >= CONST_SUBJECT_FATAL_EMERGENCY)
  {
    $subject = "FATAL emergency ! Alert from " . $lastCheck . " - " . $actualTime;
  }
  else if ($priority_two >= CONST_SUBJECT_WARNING)
  {
    $subject = "Warning Alert from " . $lastCheck . " - " . $actualTime;
  }
  else
  {
    $subject = "Alert from " . $lastCheck . " - " . $actualTime;
  }

  $file = $path.$filename;
  $content = file_get_contents($file);
  $content = chunk_split(base64_encode($content));
  $uid = md5(uniqid(time()));
  $name = basename($file);

  $header = "From: ".$fromName." <".$fromMail.">\r\n";
  $header .= "MIME-Version: 1.0\r\n";
  $header .= "Content-Type: multipart/mixed; boundary=\"".$uid."\"\r\n\r\n";

  $message = "<html>";
  $message .= "<body>";

  $message .="<h1 style='text-align:center;font-weight:bold;font-size:19px;'>Snort Alert analyse</h1><br></br>";
  $message .="<p>Timestamp between : <span style='font-weight:bold;font-size:15px;'>". $lastCheck ."  -  ". $actualTime ." </span></p><br></br>";

  if($totalAlerts >= 200)
  {
    $message .="<p>As total <span style='color:red;font-weight:bold;'> ". $totalAlerts ." </span> Alerts with <span style='color:green;font-weight:bold;'> ". count($signatures) ." </span> diferent signatures.</p><br></br>";
  }
  else if($totalAlerts > 75)
  {
    $message .="<p>As total <span style='color:orange;font-weight:bold;'> ". $totalAlerts ." </span> Alerts with <span style='color:green;font-weight:bold;'> ". count($signatures) ." </span> diferent signatures.</p><br></br>";
  }
  else
  {
    $message .="<p>As total <span style='color:green;font-weight:bold;'> ". $totalAlerts ." </span> Alerts with <span style='color:green;font-weight:bold;'> ". count($signatures) ." </span> diferent signatures.</p><br></br>";
  }


  $message .= "<table style='border-style:solid;border-width:2px;'>";
  $message .= "<tr>";
  $message .= "<td>Priority 1 :  </td>";
  $message .= "<td style='color:red;font-weight:bold;'>". $priority_one ."</td>";
  $message .= "<td> alert(s)</td>";
  $message .= "</tr>";
  $message .= "<tr>";
  $message .= "<td>Priority 2 :  </td>";
  $message .= "<td style='color:orange;font-weight:bold;'>". $priority_two ."</td>";
  $message .= "<td> alert(s)</td>";
  $message .= "</tr>";
  $message .= "<tr>";
  $message .= "<td>Priority 3 :  </td>";
  $message .= "<td style='color:green;font-weight:bold;'>". $priority_three ."</td>";
  $message .= "<td> alert(s)</td>";
  $message .= "</tr>";
  $message .= "</table>";
  $message .= "<br></br>For more details take a look on the CSV file.";
  $message .= "</body>";
  $message .= "</html>";

  $nmessage = "--".$uid."\r\n";
  $nmessage .= "Content-type:text/html; charset=iso-8859-1\r\n";
  $nmessage .= "Content-Transfer-Encoding: 7bit\r\n\r\n";
  $nmessage .= $message."\r\n\r\n";
  $nmessage .= "--".$uid."\r\n";
  $nmessage .= "Content-Type: application/octet-stream; name=\"".$filename."\"\r\n";
  $nmessage .= "Content-Transfer-Encoding: base64\r\n";
  $nmessage .= "Content-Disposition: attachment; filename=\"".$filename."\"\r\n\r\n";
  $nmessage .= $content."\r\n\r\n";
  $nmessage .= "--".$uid."--";

  if (mail($mailTo, $subject, $nmessage, $header)) {
      echo "send mail ..... OK", PHP_EOL;
  } else {
      echo "Fatal error : cannot send mail", PHP_EOL;
  }
}

function construct_Link($signature)
{
  $link = 'http://' . CONST_SERVER_IP .'/base/base_qry_main.php?new=1amp&sig%5B0%5D=%3D&sig%5B1%5D=' . $signature . "&sig_type=1&submit=Query+DB&num_result_rows=-1";
  $hyperLink = "=LIEN_HYPERTEXTE" . "(\"$link\")";

  return $hyperLink;
}

?>
