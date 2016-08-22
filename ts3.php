<?php

$path = dirname(__FILE__) . '/';

$nickNames = array(
    "fuck",
    "noob",
    "connard",
    "fdp",
    "pute",
    "mère",
    "père",
    "abruti",
    "débile",
    "crétin",
    "idiot",
    "bite",
    "grosse",
    "fils",
    "enculé",
    "emeute"
);

$adminID = array(
    10,
    6,
    32
);

$fp = fsockopen("127.0.0.1", 10011, $errno, $errstr, 0.1);
stream_set_timeout($fp, 0, 100000);

if($fp)
{
    send("login <LOGIN> <PASSWORD>");
    send("use sid=<SERVER_ID>");
    send("clientupdate client_nickname=<Nickname_Security>");

    // Mise à jour de la base de données alloclist
    $currentDate    = date('dmY');
    if(file_exists($path . '/' . 'update.txt'))
    {
        $updateArray    = file($path . '/' . 'update.txt');
        $dateUpdate     = trim($updateArray[0]);

        if($dateUpdate != $currentDate)
        {
            $alloclistDownload = file_get_contents('http://ftp.ripe.net/ripe/stats/membership/alloclist.txt');
            if($alloclistDownload)
            {
                $alloclistFilename = $path . "alloclist.txt";

                if(file_exists($alloclistFilename))
                {
                    unlink($alloclistFilename);
                } else
                {
                    send("sendtextmessage targetmode=3 target=1 msg=" . textMessage("Aucune base de données alloclist trouvée. Erreur dans la procédure."));
                }

                $file = fopen($alloclistFilename, "w");
                fputs($file, $alloclistDownload);
                fclose($file);

                if(file_exists($alloclistFilename))
                {
                    send("sendtextmessage targetmode=3 target=1 msg=" . textMessage("Base de données alloclist mise à jour avec succès."));
                }
            } else
            {
                send("sendtextmessage targetmode=3 target=1 msg=" . textMessage("Erreur dans le téléchargement de la base de données du 'alloclist'. Mise à jour impossible."));
            }

            $file = fopen($path . '/' . 'update.txt', "w");
            fputs($file, $currentDate);
            fclose($file);

            send("sendtextmessage targetmode=3 target=1 msg=" . textMessage("Maintenance journalière terminée."));
        }
    } else
    {
        $file = fopen($path . '/' . 'update.txt', "w");
        fputs($file, $currentDate);
        fclose($file);
    }

    // Traitement des clients connectés sur le serveur TeamSpeak
    $clients = getClients();

    // Vérification des doubles connexions sur le serveur TeamSpeak (mêmes adresses IP)
    checkDoubleConnections($clients);

    // Traitement des requêtes serveurs
    $server = getServerInformation();

    // Calcul du pourcentage des utilisateurs en ligne sur le serveur TeamSpeak
    $maxOnline              = $server['virtualserver_maxclients'];
    $userOnline             = $server['virtualserver_clientsonline'];
    $percentageUserOnline   = round(( $userOnline * 100 ) / $maxOnline);

    foreach ($clients as $line)
    {
        // Auto reconnaissance des administrateurs
        $isAnAdmin = false;
        foreach ($adminID as $adminIDline)
        {
            if(!empty($line['client_servergroups']))
            {
                if($line['client_servergroups'] == $adminIDline)
                {
                    $isAnAdmin = true;
                    break;
                }
            }
        }

        if($isAnAdmin === false)
        {
            if(!empty($line['connection_client_ip']))
            {
                // AFK Protection
                if($line['client_idle_time'] > ( 30 * 60000 ))
                {
                    send("clientmove clid=" . $line['clid'] . " cid=24");
                }

                // AFK Auto-Kick
                if($percentageUserOnline >= 80)
                {
                    if($line['client_idle_time'] > ( ( 60 * 2 ) * 60000 ))
                    {
                        send("sendtextmessage targetmode=1 target=" . $line['clid'] . " msg=" . textMessage("Le serveur TeamSpeak est plein à " . $percentageUserOnline . " %, vous étiez absent depuis plus d'une heure alors nous vous avons éjecté sur serveur TeamSpeak afin de pouvoir libérer des slots. Merci pour votre compréhension."));
                        send("clientkick clid=" . $line['clid'] . " reasonid=5 reasonmsg=" . textMessage("Absent pendant 2 heures ; Libération des slots automatiques
                        "));
                    }
                }

                // Vérification de la connexion
                if(isAlreadyScan(0, (3600 * 24), $line['clid'] . '.' . $line['connection_client_ip']) === FALSE)
                {
                    // Affichage d'un message en console
                    echo $line['client_nickname'] . ' (groupID: ' . $line['client_servergroups'] . ') -> ' . 'Scanné.' . "\n";

                    // Vérification du temps de connexion sur le serveur
                    /*
                    if($line['client_created'] > (60000 * 5))
                    {
                        echo $line['client_nickname'] . ' ->' . ' Utilisateur déjà scanné et trop vieux' . "\n";

                        continue;
                    }
                    */

                    // Intialisation des crédits pour l'utilisateur
                    $reason     = array();
                    $explain    = array();
                    $credit     = 0;
                    $kicked     = false;

                    // Initialisation des variables
                    $client_unique_identifier   =   sha1($line['client_unique_identifier']);
                    $f                          =   $path . 'users/' . $client_unique_identifier;

                    // Ignore les utilisateurs via les identifiants
                    if(file_exists($path . 'exception/' . $client_unique_identifier))
                    {
                        echo $line['client_nickname'] . ' (groupID: ' . $line['client_servergroups'] . ') -> ' . 'Ignoré.' . "\n";

                        continue;
                    }

                    // Envoi du welcome message
                    //send("sendtextmessage targetmode=1 target=" . $line['clid'] . " msg=" . textMessage("Bienvenue sur le serveur TeamSpeak. Votre adresse IP " . $line['connection_client_ip'] . " est vérifiée afin de trouver la présence éventuelle de VPN et de Proxy sur votre connexion Internet."));

                    // Vérification si l'utilisateur est en auto-ban
                    if($line['client_servergroups'] == 37)
                    {
                        $reason[] = 'Trolleur identifié';
                        $credit = 100;
                    }

                    // Scan de l'adresse IP de l'utilisateur
                    if(dnsBlacklist($line['connection_client_ip']))
                    {
                        $reason[] = 'Adresse IP contenue dans les DNSBL comme OpenProxy/OpenVPN';
                        $explain[] = "Si vous voyez le message (adresse IP contenue dans les DNSBL), c'est que vous utilisez un proxy, un VPN ou que votre adresse IP est connue pour envoyer du spam. Nous vous invitons à vérifier que vos ordinateurs/réseaux ne sont pas infectés par un virus.";
                        $credit++;
                    }

                    // Vérification de l'utilisateur dans la base RIPE (alloclist)
                    $alloclist = alloclist($line['connection_client_ip']);

                    if(empty($alloclist))
                    {
                        $reason[] = 'Adresse IP non contenue dans la base de données alloclist (adresse IP non européenne)';
                        $explain[] = "Votre adresse IP n'est pas contenue dans la base de données des adresses IP attribuée par l'organisation RIPE. En conclusion, vous êtes en dehors de l'Europe.";
                        $credit++;
                    }

                    // Test si un pseudo est interdit
                    foreach ($nickNames as $value)
                    {
                        if(preg_match("/" . $value . "/i", accentDelete($line['client_nickname'])))
                        {
                            $reason[] = 'Pseudonyme interdit (' . $value . ')';
                            $explain[] = "Le pseudonyme " . $value . " est interdit sur ce serveur TeamSpeak. Merci de le changer et de vous reconnecter.";
                            $credit++;
                            $kicked = true;
                        }
                    }

                    if($credit == 0)
                    {
                        //send("sendtextmessage targetmode=1 target=" . $line['clid'] . " msg=" . textMessage("-- Nous n'avons trouvé aucun problème de sécurité sur votre connexion Internet."));
                    } else
                    {
                        send("sendtextmessage targetmode=1 target=" . $line['clid'] . " msg=" . textMessage("-- Nous avons trouvé les problèmes suivants sur votre connexion Internet :"));

                        foreach ($reason as $value)
                        {
                            send("sendtextmessage targetmode=1 target=" . $line['clid'] . " msg=" . textMessage("----> " . $value));
                        }

                        foreach ($explain as $value)
                        {
                            send("sendtextmessage targetmode=1 target=" . $line['clid'] . " msg=" . textMessage('--> ' . $value));
                        }
                    }

                    if($credit > 1)
                    {
                        kick($line['clid'], $line['connection_client_ip'], '(C: ' . $credit . ') ' . $reason[0]);
                    }

                    if($kicked === TRUE)
                    {
                        kick($line['clid'], $line['connection_client_ip'], '(C: ' . $credit . ') ' . $reason[0]);
                    }

                    // END
                }
            }
        }
    }

    send("quit");
}

/**
 * Fonctions du programme
 */

function isAlreadyScan ($credit, $timeout, $data)
{
    global $path;

	$rep = "alreadyScan";
	$f = $path . $rep . '/ip.' . $data;

	$dir = opendir($rep);

	while ($fread = readdir($dir))
	{
		if($fread != "." && $fread != "..")
		{
			if(filemtime($rep . '/' . $fread) + $timeout < time())
			{
				unlink($rep . '/' . $fread);
			}
		}
	}

	if(file_exists($f))
	{
		return true;
	}

    $fp = fopen($f, "w");
    fputs($fp, $credit);
    fclose($fp);

    return false;
}

function textMessage ($i)
{
    return str_replace(array(" "), '\s', $i);
}

function send ($l)
{
    global $fp;
    usleep(100000);
    fwrite($fp, $l . "\r\n");
}

function dnsBlacklist ($ip, $timeout = 1)
{
    $servers = array(
        "misc.dnsbl.sorbs.net",
        "socks.dnsbl.sorbs.net",
        "misc.dnsbl.sorbs.net",
        "cbl.abuseat.org",
        "tor.dnsbl.sectoor.de",
        "torexit.dan.me.uk",
        "rbl.efnet.org"
    );

    foreach ($servers as $serverSel)
    {
        $response = array();
     	$host = implode(".", array_reverse(explode('.', $ip))).'.'.$serverSel.'.';
     	$cmd = sprintf('nslookup -type=A -timeout=%d %s 2>&1', $timeout, escapeshellarg($host));
     	@exec($cmd, $response);

     	for ($i = 3 ; $i < count($response) ; $i++)
        {
     		if (strpos(trim($response[$i]), 'Name:') === 0)
            {
     			return true;

                break;
     		}
     	}
    }

    return false;
}

function checkDoubleConnections ($clients)
{
    global $fp;

    $ipList     = array();
    $clidList   = array();
    $collectionList = array();
    foreach ($clients as $line)
    {
        if(!empty($line['connection_client_ip']))
        {
            $ipList[]   = $line['connection_client_ip'];
            $clidList[] = $line['clid'];

            $collectionList[] = array(
                "clid"      =>      $line['clid'],
                "ip"        =>      $line['connection_client_ip']
            );
        }
    }

    foreach (array_count_values($ipList) as $ip => $count)
    {
        if($count > 1)
        {
            foreach ($collectionList as $value)
            {
                if($value['ip'] == $ip)
                {
                    kick($value['clid'], $ip, 'Trop de connexions simultanées depuis la même adresse IP', true);
                }
            }
        }
    }
}

function getClients ()
{
    global $fp, $path;

    // Traitement des clients
    send("clientlist -ip -times -groups -info");

    $clientList = null;
    while ($line = fgets($fp))
    {
            $clientList .= $line;
    }

    $clientList         = strstr($clientList, "error id=0 msg=ok");
    $clientList         = trim(str_replace(array('error id=0 msg=ok'), "", $clientList));
    $clientsArray       = explode("|", $clientList);

    $clients = array();
    foreach ($clientsArray as $line)
    {
        $lineArray = explode(" ", $line);

        $tableTemp = array();
        foreach ($lineArray as $txt)
        {
            $var        = strstr($txt, '=', true);
            $value      = substr(strstr($txt, '=', false), 1);

            $tableTemp[trim($var)] = trim($value);
        }

        // Récupération des informations supplémentaires sur l'utilisateur
        if(!empty($tableTemp['connection_client_ip']))
        {
            if(file_exists($path . 'alreadyScan' . '/ip.' . $tableTemp['clid'] . '.' . $tableTemp['connection_client_ip']) === FALSE)
            {
                // Récupération des données sur l'utilisateur (unique ID)
                send("clientinfo clid=" . $tableTemp['clid']);

                $infoUserList = null;
                while ($line = fgets($fp))
                {
                        $infoUserList .= $line;
                }

                $infoUserListArray = explode(" ", $infoUserList);

                // Construction du tableau avec les informations utilisateurs
                foreach ($infoUserListArray as $txt)
                {
                    $var        = strstr($txt, '=', true);
                    $value      = substr(strstr($txt, '=', false), 1);

                    if($var == "client_unique_identifier")
                    {
                        $tableTemp[trim($var)] = trim($value);
                        break;
                    }
                }

                // END
            }
        }

        $clients[] = $tableTemp;

        unset($tableTemp, $var, $value, $infoUserList, $infoUserListArray, $clientList);
    }

    return $clients;
}

function getServerInformation ()
{
    global $fp;

    send("serverinfo");

    $server = null;
    $serverList = null;
    while ($line = fgets($fp))
    {
            $serverList .= $line;
    }

    $serverList         = trim(str_replace(array('error id=0 msg=ok'), "", $serverList));
    $serverArray        = explode("|", $serverList);

    $server = null;
    foreach ($serverArray as $line)
    {
        $lineArray = explode(" ", $line);

        $tableTemp = array();
        foreach ($lineArray as $txt)
        {
            $var        = strstr($txt, '=', true);
            $value      = substr(strstr($txt, '=', false), 1);

            $tableTemp[trim($var)] = trim($value);
        }

        $server = $tableTemp;

        unset($tableTemp, $var, $value);
    }

    return $server;
}

function alloclist ($ip)
{
    global $path;

    $ip = ip2long($ip);
    $fichier = $path . "alloclist.txt";
    $tableau = file($fichier);

    foreach($tableau as $i => $ligne)
    {
        $ligne = trim($ligne);
        $pos = strpos($ligne, "ALLOCATED");

        if($pos)
        {
            $plage = substr($ligne, 9, $pos - 10);
            $pos = strpos($plage, "/");
            $reseau = substr($plage, 0, $pos);
            $points = substr_count($reseau, ".");

            if($points == 0) $reseau .= ".0.0.0";
            if($points == 1) $reseau .= ".0.0";
            if($points == 2) $reseau .= ".0";

            $reseau = ip2long($reseau);
            $masque = substr($plage, $pos + 1);
            $masque = 4294967296 - pow(2, 32 - $masque);

            if(($ip & $masque) == ($reseau & $masque))
            {
                $masque = long2ip($masque);
                $date = substr($ligne, 6, 2)."/".substr($ligne, 4, 2)."/".substr($ligne, 0, 4);
                $ripe = "$plage $date $proprietaire";

                return $ripe;
            }
        } else
        {
            if(substr($ligne, 2, 1) == ".") $proprietaire = trim($tableau[$i + 1])." $ligne";
        }
    }
}

function accentDelete ($str)
{
    $str = strtr($str, 'ÁÀÂÄÃÅÇÉÈÊËÍÏÎÌÑÓÒÔÖÕÚÙÛÜÝ', 'AAAAAACEEEEEIIIINOOOOOUUUUY');
    $str = strtr($str, 'áàâäãåçéèêëíìîïñóòôöõúùûüýÿ', 'aaaaaaceeeeiiiinooooouuuuyy');

    return $str;
}

function AntiFlood ($credit, $timeout, $data)
{
    global $path;

	$rep = $path . "count/";
	$f = $path . 'count/' . '/ip.' . $data;

	$dir = opendir($rep);

	while ($fread = readdir($dir))
	{
		if($fread != "." && $fread != "..")
		{
			if(filemtime($rep . '/' . $fread) + $timeout < time())
			{
				unlink($rep . '/' . $fread);
			}
		}
	}

	if(file_exists($f))
	{
		$c = file($f);
		$c = $c[0];
	} else
	{
		$fp = fopen($f, "w");
		fputs($fp, $credit);
		fclose($fp);
		$c = $credit;
	}

	$c--;

	$fp = fopen($f, "w");
	fputs($fp, $c);
	fclose($fp);

	if($c < 0)
	{
		return TRUE;
	}
}

function kick ($clid, $ip, $reason, $onlyKick = false)
{
    global $fp;

    if($onlyKick === TRUE)
    {
        send("clientkick clid=" . $clid . " reasonid=5 reasonmsg=" . textMessage($reason));

        return 0;
    }

    if(AntiFlood(3, (3600 * 24), $ip) === TRUE)
    {
        send("sendtextmessage targetmode=1 target=" . $clid . " msg=" . textMessage("ATTENTION : Vous avez été banni du serveur pour récidive !"));
        send("banclient clid=" . $clid . " time=" . (60 * 60) . " banreason=" . textMessage($reason));
    } else
    {
        send("sendtextmessage targetmode=1 target=" . $clid . " msg=" . textMessage("ATTENTION : Vous avez éjecté du serveur et ceci est le *Premier avertissement* !"));
        send("clientkick clid=" . $clid . " reasonid=5 reasonmsg=" . textMessage($reason));
    }
}

?>
