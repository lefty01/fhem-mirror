################################################################
#
#  based / modified Version 98_EGPMS2LAN from ericl
#  and based on 17_EGPM2LAN.pm Alex Storny (moselking at arcor dot de)
#
#  (c) 2016,2018 Copyright: Andreas Loeffler (al@exitzero.de)
#  All rights reserved
#
#  This script free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  any later version.
#
#  The GNU General Public License can be found at
#  http://www.gnu.org/copyleft/gpl.html.
#
#  This script is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
################################################################
#  -> Module 70_EGPM.pm (for a single Socket) needed.
################################################################
package main;

use strict;
use warnings;
use HttpUtils;

sub
ePowerSwitch_Initialize($)
{
  my ($hash) = @_;

  $hash->{GetFn}    = "ePowerSwitch_Get";
  $hash->{SetFn}    = "ePowerSwitch_Set";
  $hash->{DefFn}    = "ePowerSwitch_Define";
  $hash->{UndefFn}  = "ePowerSwitch_Undefine";
  $hash->{AttrList} = $readingFnAttributes;
}


################################
sub ePowerSwitch_StorePassword($$)
{
  my ($hash, $password) = @_;

  my $index = $hash->{TYPE} . "_" . $hash->{NAME} . "_passwd";
  my $key = getUniqueId() . $index;
  my $enc_pwd = "";

  if (eval "use Digest::MD5;1") {
    $key = Digest::MD5::md5_hex(unpack "H*", $key);
    $key .= Digest::MD5::md5_hex($key);
  }

  for my $char (split //, $password) {
    my $encode = chop($key);
    $enc_pwd .= sprintf("%.2x", ord($char)^ord($encode));
    $key = $encode . $key;
  }

  Log3 "ePowerSwitch", 0, "write password to file uniqueID";
  my $err = setKeyValue($index, $enc_pwd);
  if (defined($err)){
    #Fallback, if file is not available
    $hash->{PASSWORD} = $password;
    return "ePowerSwitch: Write Password failed!";
  }
  $hash->{PASSWORD} = "***" if ($password ne "");
  return "ePowerSwitch: Password saved.";
}

################################
sub ePowerSwitch_ReadPassword($)
{
  my ($hash) = @_;

  #for old installations/fallback to clear-text PWD
  if (defined($hash->{PASSWORD}) && $hash->{PASSWORD} ne "***"){
    return $hash->{PASSWORD};
  }

  my $index = $hash->{TYPE} . "_" . $hash->{NAME} . "_passwd";
  my $key = getUniqueId() . $index;
  my ($password, $err);

  Log3 "ePowerSwitch", 0, "Read password from file uniqueID";
  ($err, $password) = getKeyValue($index);

  if (defined($err)) {
    Log3 "ePowerSwitch", 0, "unable to read password from file: $err";
    return undef;
  }

  if (defined($password)) {
    if (eval "use Digest::MD5;1") {
      $key = Digest::MD5::md5_hex(unpack "H*", $key);
      $key .= Digest::MD5::md5_hex($key);
    }

    my $dec_pwd = '';

    for my $char (map { pack('C', hex($_)) } ($password =~ /(..)/g)) {
      my $decode = chop($key);
      $dec_pwd .= chr(ord($char) ^ ord($decode));
      $key = $decode . $key;
    }

    $hash->{PASSWORD} = "***";
    return $dec_pwd;
  }
  else {
    Log3 "ePowerSwitch", 0, "No password in file";
    return "";
  }
}
###################################

sub ePowerSwitch_Define($$) {
  my ($hash, $def) = @_;
  my @a = split("[ \t][ \t]*", $def);

  my $u = "wrong syntax: define <name> ePowerSwitch IP [Password]";
  return $u if (int(@a) < 2);

  $hash->{IP} = $a[2];
  if (int(@a) == 4) {
    ePowerSwitch_StorePassword($hash, $a[3]);
    $hash->{DEF} = $a[2];
  }

  my $result = ePowerSwitch_Login($hash);
  if ($result == 1) {
    $hash->{STATE} = "initialized";
    ePowerSwitch_Statusrequest($hash, 0);
    ePowerSwitch_Logoff($hash);
  }
  else {
    $hash->{STATE} = "undefined";
  }
  return undef;
}

sub ePowerSwitch_Undefine($$) {
  # FIXME
  return undef;
}


###################################
sub
ePowerSwitch_Get($@)
{
  my ($hash, @a) = @_;
  my $what;

  return "argument is missing" if (int(@a) != 2);

  $what = $a[1];

  if ($what eq "state") {
    if (defined($hash->{STATE})) {
      return $hash->{STATE};
    }
  }
  elsif ($what eq "lastcommand") {
    if (defined($hash->{READINGS}{lastcommand}{VAL})) {
      return $hash->{READINGS}{lastcommand}{VAL};
    }
  }
  else {
    return "Unknown argument $what, choose one of state:noArg lastcommand:noArg"
	. (exists($hash->{READINGS}{output}) ? " output:noArg" : "");
  }
  return "";
}

###################################
sub
ePowerSwitch_Set($@)
{
  my ($hash, @a) = @_;

  return "no set value specified" if (int(@a) < 2);
  return "Unknown argument $a[1], choose one of on:1,2,3,4,all off:1,2,3,4,all"
      ." toggle:1,2,3,4 clearreadings:noArg statusrequest:noArg password" if ($a[1] eq "?");

  my $name = shift @a;
  my $setcommand = shift @a;
  my $params = join(" ", @a);

  Log3 "ePowerSwitch", 3, "set $name (". $hash->{IP}. ") $setcommand $params";

  ePowerSwitch_Login($hash);

  if ($setcommand eq "on" || $setcommand eq "off") {
    if ($params eq "all") {
      for (my $count = 1; $count <= 4; $count++) {
	ePowerSwitch_Switch($hash, $setcommand, $count);
      }
    }
    else {  # switch single Socket (params=1,2,3,or 4)
      ePowerSwitch_Switch($hash, $setcommand, $params);
    }
    ePowerSwitch_Statusrequest($hash, 1);
  }
  elsif ($setcommand eq "toggle") { ### FIXME ...
    my $stateref = ePowerSwitch_Statusrequest($hash, 1);
    if (defined($stateref)) {
      Log3 "ePowerSwitch_Statusrequest", 1, "socket $params=" . $stateref->{$params} . "\n";
      my $newcommand = "off";
      if ($stateref->{$params} == 0) {
	$newcommand = "on";
      }
      ePowerSwitch_Switch($hash, $newcommand, $params);
      ePowerSwitch_Statusrequest($hash, 0);
    }
  }
  elsif ($setcommand eq "statusrequest") {
    ePowerSwitch_Statusrequest($hash, 1);
  }
  elsif ($setcommand eq "clearreadings") {
    delete $hash->{READINGS};
  }
  elsif($setcommand eq "password") {
    my $result = ePowerSwitch_StorePassword($hash, $params);
    Log3 "ePowerSwitch", 0, $result;
    if ($params eq "") {
      delete $hash->{PASSWORD} if(defined($hash->{PASSWORD}));
    } else {
      $params="***";
    }
  }
  else {
    return "unknown argument $setcommand, choose one of on, off, toggle, statusrequest, clearreadings";
  }

  ePowerSwitch_Logoff($hash);

  $hash->{CHANGED}[0] = $setcommand;
  $hash->{READINGS}{lastcommand}{TIME} = TimeNow();
  $hash->{READINGS}{lastcommand}{VAL} = $setcommand . " " . $params;

  return undef;
}

################################
sub ePowerSwitch_Switch($$$) {
  my ($hash, $state, $port) = @_;
  my $data;
  my $response;
  my $keepalive = 1;

  $state = ($state eq "on" ? "1" : "0");
  Log3 "ePowerSwitch", 0, "Switch(): state=$state";

  # port may only be one of 1, 2, 3, or 4
  if ($port eq "1" or $port eq "2" or $port eq "3" or $port eq "4") {
    $data = "P$port=$state";
  } else {
    Log3 "ePowerSwitch", 0, "Switch() invalid port: $port (only 1..4)";
    return 0;
  }
  Log3 "ePowerSwitch", 0, "Switch(): data=$data";

  eval {
    # Parameter: $url, $timeout, $data, $noshutdown=0, $loglevel=4
    $response = GetFileFromURL("http://" . $hash->{IP} . "/econtrol.html", 5, $data, $keepalive);
  };
  if ($@) {
    ### catch block
    Log3 "ePowerSwitch", 0, "Switch(): ERROR: $@";
  } else {
    Log3 "ePowerSwitch", 3, "Switch(): switch command OK";
    Log3 "ePowerSwitch", 4, "Switch(): response: $response" if (defined $response);
  }

  return 1;
}

################################
sub ePowerSwitch_Login($) {
  my ($hash) = @_;
  my $passwd = ePowerSwitch_ReadPassword($hash);
  my $keepalive = 1;

  Log3 "ePowerSwitch", 0, "try to Login @" . $hash->{IP};

  eval {
    # Parameter: $url, $timeout, $data, $noshutdown, $loglevel
    GetFileFromURL("http://" . $hash->{IP} . "/elogin.html", 5,
		   "pwd=" . (defined($passwd) ? $passwd : ""), $keepalive, 0);
  };
  if ($@) {
      ### catch block
      Log3 "ePowerSwitch", 0, "Login error: $@";
      return 0;
  }
  Log3 "ePowerSwitch", 0, "Login successful!";

  return 1;
}

################################

sub ePowerSwitch_Statusrequest($) {
  my ($hash) = @_;
  my $name = $hash->{NAME}; # device name
  my $keepalive = 1;
  Log3 "ePowerSwitch", 0, "Statusrequest() devicename=$name";

  my $response = GetFileFromURL("http://" . $hash->{IP} . "/econtrol.html", 5, "", $keepalive);

  if (not defined($response)) {
     Log3 "ePowerSwitch", 0, "Statusrequest() for $name Cant connect to " . $hash->{IP};
     $hash->{STATE} = "no response";
     return 0
  }
  Log3 "ePowerSwitch", 4, "Statusrequest: response=" . $response;

  my %socketstates;
  while ($response =~ m/\s*.*<TD align=right class=(ON|OF)>switch(\d)\s*<\/TD>/gi) {
    my $socketstate = trim($1) eq "ON" ? 1 : 0;
    my $socketnum   = trim($2);
    $socketstates{$socketnum} = $socketstate;
    Log3 "ePowerSwitch", 4, "Statusrequest: socket: $socketnum is $socketstate";
  }

  # fixme attr num sockets?
  my $size = keys %socketstates;
  if ($size < 4) {
    $hash->{STATE} = "no valid response";
    Log3 "ePowerSwitch", 3, "no valid response";
  }
  else {
    my $statusstring = "";
    readingsBeginUpdate($hash);
    foreach my $sock (keys %socketstates) {
      Log3 "ePowerSwitch", 3, "socket $sock is $socketstates{$sock}";
      $statusstring .= "S$sock:$socketstates{$sock},";

      readingsBulkUpdateIfChanged($hash, 'S'.$sock, $socketstates{$sock});
    }
    readingsEndUpdate($hash, 1);

    #everything is fine
    $statusstring =~ s/,$//;
    $hash->{STATE} = $statusstring;
    return \%socketstates;
  }
  #something went wrong :-(
  return undef;
}

sub ePowerSwitch_Logoff($) {
  my ($hash) = @_;
  # econtrol.html or elogin.html ??
  eval{
    GetFileFromURL("http://" .$hash->{IP} . "/econtrol.html", 5, "X=   Exit   ", 0, 0);
  };
  if ($@){
    ### catch block
    Log3 "ePowerSwitch", 0, "Logoff error: $@";
    return 0;
  };
  Log3 "ePowerSwitch", 1, "Logoff successful!";

  return 1;
}


1;

=pod
=begin html

<a name="ePowerSwitch"></a>
<h3>ePowerSwitch</h3>
<ul>
  <br>
  <a name="ePowerSwitchdefine"></a>
  <b>Define</b>
  <ul>
    <code>define &lt;name&gt; ePowerSwitch &lt;IP-Address&gt; [&lt;Password&gt;]</code><br>
    <br>
    Creates a Leunig &reg; <a href="http://www.leunig.de/_pro/remote_power_switches.html" >ePowerSwitch</a> device to switch up to 4 sockets over the network.
    Please make sure that you&acute;re logged off from the ePowerSwitch web-interface otherwise you can&acute;t control it with FHEM at the same time.<br>
</ul><br>
  <a name="ePowerSwitchset"></a>
  <b>Set</b>
  <ul>
    <code>set &lt;name&gt; &lt;[on|off|toggle]&gt &lt;socketnr.&gt;</code><br>
    Switch the socket on or off.<br>
    <br>
    <code>set &lt;name&gt; &lt;[on|off]&gt &lt;all&gt;</code><br>
    Switch all available sockets on or off.<br>
    <br>
    <code>set &lt;name&gt; &lt;staterequest&gt;</code><br>
    Update the device information and the state of all sockets.<br>
    <br>
    <code>set &lt;name&gt; &lt;clearreadings&gt;</code><br>
    Removes all readings from the list.
  </ul>
  <br>
  <a name="ePowerSwitchget"></a>
  <b>Get</b> <ul>N/A</ul><br>

  <a name="ePowerSwitchattr"></a>
  <b>Attributes</b>
  <ul>
    <li><a href="#readingFnAttributes">readingFnAttributes</a></li>
  </ul>
  <br>
<br>
   <br>

    Example:
    <ul>
      <code>define mainswitch ePowerSwitch 10.192.192.20 SecretGarden</code><br>
      <code>set mainswitch on 1</code><br>
    </ul>
</ul>

=end html
=begin html_DE

<a name="ePowerSwitch"></a>
<h3>ePowerSwitch</h3>
<ul>
  <br>
  <a name="ePowerSwitchdefine"></a>
  <b>Define</b>
  <ul>
    <code>define &lt;name&gt; ePowerSwitch &lt;IP-Address&gt; [&lt;Password&gt;]</code><br>
    <br>
    Das Modul erstellt eine Verbindung zu einer Leunig &reg; <a href="http://www.leunig.de/_pro/remote_power_switches.html" >ePowerSwitch</a> Steckdosenleiste und steuert 4 angeschlossene Ger&auml;te..
    Bitte darauf achten, die Weboberfl&auml;che mit <i>Logoff</i> wieder zu verlassen, da der Zugriff sonst blockiert wird.
</ul><br>
  <a name="ePowerSwitchset"></a>
  <b>Set</b>
  <ul>
    <code>set &lt;name&gt; &lt;[on|off|toggle]&gt &lt;socketnr.&gt;</code><br>
    Schaltet die gew&auml;hlte Steckdose ein oder aus.<br>
    <br>
    <code>set &lt;name&gt; &lt;[on|off]&gt &lt;all&gt;</code><br>
    Schaltet alle Steckdosen gleichzeitig ein oder aus.<br>
    <br>
    <code>set &lt;name&gt; &lt;staterequest&gt;</code><br>
    Aktualisiert die Statusinformation der Steckdosenleiste.<br>
    <br>
    <code>set &lt;name&gt; &lt;clearreadings&gt;</code><br>
    L&ouml;scht alle ung&uuml;ltigen Eintr&auml;ge im Abschnitt &lt;readings&gt;.
  </ul>
  <br>
  <a name="ePowerSwitchget"></a>
  <b>Get</b> <ul>N/A</ul><br>

  <a name="ePowerSwitchattr"></a>
  <b>Attribute</b>
  <ul>
    <li><a href="#readingFnAttributes">readingFnAttributes</a></li>
  </ul>
  <br>
<br>
   <br>
    Beispiel:
    <ul>
      <code>define sleiste ePowerSwitch 10.192.192.20 geheim</code><br>
      <code>set sleiste on 1</code><br>
    </ul>
</ul>
=end html_DE

=cut
