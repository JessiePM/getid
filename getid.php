<?php

// *** Mj - Récupération du login Windows via l'entête http *** \\
function GetNTLMInfo() {
    $headers = apache_request_headers(); // Mj - recupère toutes les entêtes HTTP de la requête sous forme de tableau
	if (!isset($headers['Authorization'])){ // Mj - si le champ authorization est vide, erreur et exit
		header('HTTP/1.1 401 Unauthorized');
		header('WWW-Authenticate: NTLM');
		exit;
	}

	$auth = $headers['Authorization']; // Mj - $auth récupère l'élément authorization du tableau

	if (substr($auth,0,5) == 'NTLM ') { // Mj - si les 5 premieres lettres sont NTLM
        $msg = base64_decode(substr($auth, 5)); // Mj - decodage

		if (substr($msg, 0, 8) != "NTLMSSP\x00")
			die('error header not recognised');

		if ($msg[8] == "\x01") { // Mj - erreur

			$msg2 = "NTLMSSP\x00\x02\x00\x00\x00".
				"\x00\x00\x00\x00". // récupération name len/alloc
				"\x00\x00\x00\x00". // récupération name offset
				"\x01\x02\x81\x00". // flags
				"\x00\x00\x00\x00\x00\x00\x00\x00". // challenge
				"\x00\x00\x00\x00\x00\x00\x00\x00". // context
				"\x00\x00\x00\x00\x00\x00\x00\x00"; // target info len/alloc/offset

			header('HTTP/1.1 401 Unauthorized');
			header('WWW-Authenticate: NTLM '.trim(base64_encode($msg2)));
			exit;
		}
		else if ($msg[8] == "\x03") {

			function get_msg_str($msg, $start, $unicode = true) {
				$len = (ord($msg[$start+1]) * 256) + ord($msg[$start]);
				$off = (ord($msg[$start+5]) * 256) + ord($msg[$start+4]);
				if ($unicode)
					return str_replace("\0", '', substr($msg, $off, $len));
				else
					return substr($msg, $off, $len);
			}
            $user = get_msg_str($msg, 36);
            $domain = get_msg_str($msg, 28);
            $workstation = get_msg_str($msg, 44);
			return (array($user, $domain, $workstation));
		}
	}
}
$NTLMInfo = GetNTLMInfo(); // Mj - récupération des données (tableau)
$login = $NTLMInfo[0]; // Mj - récupération du 1er élément du tableau correspondant à l'identifiant

?>
