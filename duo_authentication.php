<?php
/**
* Roundcube-Duo-plugin
*
* This plugin enables Duo passcode authentication within Roundcube webmail against 
* the Duo Security web service API.
*
* @author Georgios Vlachos <george (at) intermobilis.com>
* @license GPL2
*
* Acknowledgement:
*
*/

class duo_authentication extends rcube_plugin
{
  private function is_enabled()
  {
    $r = ($this->get('duo_2F') === true);
    return $r;
  }
  
  private function get($v)
  {
    return rcmail::get_instance()->config->get($v);
  }
 
  private function fail()
  {
    rcmail::get_instance()->logout_actions();
    rcmail::get_instance()->kill_session();
  } 

  function init()
  {
    $this->load_config();

    // minimal configuration validation
    $ik = $this->get('duo_ik');
    $sk = $this->get('duo_sk');
    $ah = $this->get('duo_ah');
    if ($this->is_enabled() && (empty($ik) || empty($sk) || empty($ah))) 
      throw new Exception('Duo 2F Auth configuration must be set');
    
    $this->add_texts('localization/', true);

    $this->add_hook('template_object_loginform', array($this, 'update_login_form'));
    $this->add_hook('login_after', array($this, 'login_after'));
  }

  function update_login_form($p)
  {
    if ($this->is_enabled())
      $this->include_script('duo_passcode.js');

    return $p;
  }

  private function request($uri, $method, $params) {
      $url = "https://" . $this->get('duo_ah') . $uri;
	  $date = date(DateTime::RFC2822);

      if ($method == "GET") {
          if ($params != NULL) {
              $url .= "?";
              foreach($params as $key => $value) {
                  $url .= rawurlencode($key) . "=" . rawurlencode($value) . "&";
              }
              // Remove extra amperstand
              $url = substr($url, 0, -1);
          }
      }

      $sig = $this->sign_request($date, $method, $this->get('duo_ah'), $uri, $params);
      $ch  = curl_init();

      curl_setopt($ch, CURLOPT_URL, $url);
      // curl_setopt($ch, CURLOPT_USERAGENT, "Duo_Auth");
      curl_setopt($ch, CURLOPT_HEADER, FALSE);
      curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
      curl_setopt($ch, CURLOPT_HTTPHEADER, array("Authorization: " . $sig, "Date: " .$date, "Host: " .$this->get('duo_ah')));

      if ($method == "POST") {
          curl_setopt($ch, CURLOPT_POST, count($params));
          curl_setopt($ch, CURLOPT_POSTFIELDS, $params);
      }

      curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, TRUE);
	  curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);

      // Execute the request and return the response.
      $req = curl_exec($ch);
      $http_status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
      curl_close($ch);

      return $req;
  }

  private function canon($date, $method, $host, $path, $params) {
      $canon     = array(strtoupper($method), strtolower($host), $path);
      $param_str = "";

      // Create the parameter string
      if ($params != NULL) {

          // Make sure the keys are sorted!
          ksort($params);

          foreach($params as $key => $value) {
              $param_str .= rawurlencode($key) . "=" . rawurlencode($value) . "&";
          }

          // Remove the extra amperstand
          $param_str = substr($param_str, 0, -1);
      }

      // Join them all with new lines, append the param string
	  $canon_str = $date ."\n";
      $canon_str .= join("\n", $canon);
      $canon_str .= "\n" . $param_str;

      return $canon_str;
  }

  private function sign_request($date, $method, $host, $path, $params) {
      $canon = $this->canon($date, $method, $host, $path, $params);
      $sig   = hash_hmac("sha1", $canon, $this->get('duo_sk'));
      return "Basic " . base64_encode($this->get('duo_ik') . ":" . $sig);
  }

  function login_after($args)
  {
    $user = get_input_value('_user', RCUBE_INPUT_POST);
	$client_addr = filter_var((!empty($_SERVER['HTTP_CLIENT_IP'])) ? $_SERVER['HTTP_CLIENT_IP'] : (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) ? $_SERVER['HTTP_X_FORWARDED_FOR'] : (!empty($_SERVER['REMOTE_ADDR'])) ? $_SERVER['REMOTE_ADDR'] : '0.0.0.0', FILTER_SANITIZE_STRING);

    if (!$this->is_enabled()) {
        write_log("errors", "duo: DISABLED Login from IP ".$client_addr." for User ".$user);
        return $args;
    }

    $params = array(
		"ipaddr" => $client_addr,
	    "username" => $user
    );
    $result = $this->request("/auth/v2/preauth", "POST", $params);
    $obj = json_decode($result);
    if ($obj->{'stat'} == 'OK' && $obj->{'response'}->{'result'} == 'auth') {
        $passcode = get_input_value('_duopasscode', RCUBE_INPUT_POST);
        if (empty($passcode))
        {
          write_log("errors", "duo: ERROR IP ".$client_addr." empty passcode for USER ".$user);
          $this->fail();
        }
        else
        {
            $params = array(
                "username" => $user,
                "factor" => "passcode",
                "passcode" => $passcode,
                "ipaddr" => $client_addr
            );
            $result = $this->request("/auth/v2/auth", "POST", $params);
            $obj = json_decode($result);
            if ($obj->{'stat'} == 'OK' && $obj->{'response'}->{'result'} == 'allow') {
                write_log("errors", "duo: IP ".$client_addr." for User ".$user." Passcode ".$passcode." RES ".$obj->{'response'}->{'result'});
                return $args;
            } else {
                write_log("errors", "duo: ERROR IP ".$client_addr." for User ".$user." Passcode ".$passcode." MES ".($obj->{'stat'} == 'OK' ? $obj->{'response'}->{'status_msg'} : $obj->{'message'}));
                $this->fail();
            }
        }
    }
    else
    {
        write_log("errors", "duo: ERROR IP ".$client_addr." for User ".$user." No auth user MES ".($obj->{'stat'} == 'OK' ? $obj->{'response'}->{'result'} : $obj->{'message'}));
        $this->fail();
    }

    return $args;
  }

}
?>
