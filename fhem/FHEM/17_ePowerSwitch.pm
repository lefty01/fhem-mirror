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
  $hash->{Clients}   = ":EGPM:";
  $hash->{GetFn}     = "ePowerSwitch_Get";
  $hash->{SetFn}     = "ePowerSwitch_Set";
  $hash->{DefFn}     = "ePowerSwitch_Define";
  $hash->{AttrList}  = "stateDisplay:sockNumber,sockName autocreate:on,off";
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

  return "no set value specified" if(int(@a) < 2);
  return "Unknown argument $a[1], choose one of on:1,2,3,4,all off:1,2,3,4,all toggle:1,2,3,4 clearreadings:noArg statusrequest:noArg password" if($a[1] eq "?");

  my $name = shift @a;
  my $setcommand = shift @a;
  my $params = join(" ", @a);

  Log3 "ePowerSwitch", 0, "set $name (". $hash->{IP}. ") $setcommand $params";

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
    my $currentstate = ePowerSwitch_Statusrequest($hash, 1);
    if (defined($currentstate)) {
      my @powerstates = split(",", $currentstate);
      my $newcommand = "off";
      if ($powerstates[$params - 1] eq "0") {
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
  $state = ($state eq "on" ? "1" : "0");
  Log3 "ePowerSwitch", 0, "Switch(): state=$state, data=$data";

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
    $response = GetFileFromURL("http://" . $hash->{IP} . "/econtrol.html", 5, $data, 0, 0);
    Log3 "ePowerSwitch", 0, "Switch(): response: $response";
  };
  if ($@) {
    ### catch block
    Log3 "ePowerSwitch", 0, "Switch(): ERROR: $@";
  } else {
    Log3 "ePowerSwitch", 0, "Switch(): switch command OK";
    Log3 "ePowerSwitch", 0, "Switch(): response: $response" if (defined $response);
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
    GetFileFromURL("http://" . $hash->{IP} . "/elogin.html", 5,
		   "pwd=" . (defined($passwd) ? $passwd : ""), 0, $keepalive);
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
sub ePowerSwitch_GetDeviceInfo($$) {
  my ($hash, $input) = @_;

  Log3 "ePowerSwitch", 0 ,"GetDeviceInfo: inpu=$input";
  #try to read Device Name
  my ($devicename) = $input =~ m/<h2>(.+)<\/h2><\/div>/si;
  $hash->{DEVICENAME} = trim($devicename);

  #try to read Socket Names
  my @socketlist;
  # <TD align=right class=OF>switch1
  while ($input =~ m/<TD align=right class=..>(switch\d)\w*<\/TD>/gi) {
    my $socketname = trim($1);
    $socketname =~ s/ /_/g;    #remove spaces
    push(@socketlist, $socketname);
  }

  # check for duplicate names
  my %seen;
  foreach my $entry (@socketlist) {
    next unless $seen{$entry}++;
    Log3 "ePowerSwitch", 0, "Sorry! Can't use devicenames. " . trim($entry) . " is duplicated.";
    @socketlist = qw(Socket_1 Socket_2 Socket_3 Socket_4);
  }
  if (int(@socketlist) < 4) {
    @socketlist = qw(Socket_1 Socket_2 Socket_3 Socket_4);
  }
  return @socketlist;
}

################################
sub ePowerSwitch_Statusrequest($$) {
  my ($hash, $autoCr) = @_;
  my $name = $hash->{NAME}; # device name
  Log3 "ePowerSwitch", 0, "Statusrequest() name=$name, autoCr=$autoCr";

  ##ePowerSwitch_Login($hash); # ???
  my $response = GetFileFromURL("http://" . $hash->{IP} . "/econtrol.html", 5, "", 0, 0);

  if (not defined($response)) {
     Log3 "ePowerSwitch", 0, "Statusrequest() for $name Cant connect to " . $hash->{IP};
     $hash->{STATE} = "Connection failed";
     return 0
  }
  Log3 "ePowerSwitch", 1, "Statusrequest: response=" . $response;

  if ($response =~ /.,.,.,./) {
    my $powerstatestring = $&;
    my @powerstates = split(",", $powerstatestring);

    Log3 "ePowerSwitch", 0, " Powerstates: " . $powerstatestring;

    if (int(@powerstates) == 4) {
      my $index;
      my $newstatestring;
      my @socketlist = ePowerSwitch_GetDeviceInfo($hash, $response);
      readingsBeginUpdate($hash);

      foreach my $powerstate (@powerstates) {
	$index++;
	if (length(trim($socketlist[$index-1])) == 0) {
	  $socketlist[$index-1] = "Socket_" . $index;
	}
	if (AttrVal($name, "stateDisplay", "sockNumber") eq "sockName") {
	  $newstatestring .= $socketlist[$index-1] . ": " . ($powerstates[$index-1] ? "on" : "off") . " ";
	} else {
	  $newstatestring .= $index . ": " . ($powerstates[$index-1] ? "on" : "off") . " ";
	}

	#Create Socket-Object if not available
	my $defptr = $modules{EGPM}{defptr}{$name . $index};
	if ($autoCr && AttrVal($name, "autocreate", "on") eq "on" && not defined($defptr)) {
	  if (Value("autocreate") eq "active") {
	    Log3 "ePowerSwitch", 1, "Autocreate EGPM for Socket $index";
	    CommandDefine(undef, $name . "_" . $socketlist[$index-1] . " EGPM $name $index");
	  }
	  else {
	    Log 2, "ePowerSwitch: Autocreate disabled in globals section";
	    $attr{$name}{autocreate} = "off";
	  }
	}

	#Write state 2 related Socket-Object
	if (defined($defptr)) {
	  if (ReadingsVal($defptr->{NAME}, "state","") ne ($powerstates[$index-1] ? "on" : "off")) {
	    #check for chages and update -> trigger event
	    Log3 "ePowerSwitch", 0, "Update State of " . $defptr->{NAME};
	    readingsSingleUpdate($defptr, "state", ($powerstates[$index-1] ? "on" : "off"), 1);
	  }
	  $defptr->{DEVICENAME} = $hash->{DEVICENAME};
	  $defptr->{SOCKETNAME} = $socketlist[$index-1];
	}

	readingsBulkUpdate($hash, $index."_".$socketlist[$index-1], ($powerstates[$index-1] ? "on" : "off"));
      }
      readingsBulkUpdate($hash, "state", $newstatestring);
      readingsEndUpdate($hash, 0);

      #everything is fine
      return $powerstatestring;
    }
    else {
      Log3 "ePowerSwitch", 0, "Failed to parse powerstate";
    }
  }
  else {
    $hash->{STATE} = "Login failed";
    Log3 "ePowerSwitch", 0, "Login failed";
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
  Log3 "ePowerSwitch", 0, "Logoff successful!";


  return 1;
}

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
  # else { ??

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
    If you have more than one device, it is helpful to connect and set names for your sockets over the web-interface first.
    The name settings will be adopted to FHEM and helps you to identify the sockets. Please make sure that you&acute;re logged off from the ePowerSwitch web-interface otherwise you can&acute;t control it with FHEM at the same time.<br>
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
    If <a href="#autocreate">autocreate</a> is enabled, an <a href="#EGPM">EGPM</a> device will be created for each socket.<br>
    <br>
    <code>set &lt;name&gt; &lt;clearreadings&gt;</code><br>
    Removes all readings from the list to get rid of old socketnames.
  </ul>
  <br>
  <a name="ePowerSwitchget"></a>
  <b>Get</b> <ul>N/A</ul><br>

  <a name="ePowerSwitchattr"></a>
  <b>Attributes</b>
  <ul>
    <li>stateDisplay</li>
      Default: <b>socketNumer</b> changes between <b>socketNumer</b> and <b>socketName</b> in front of the current state. Call <b>set statusrequest</b> to update all states.
    <li>autocreate</li>
    Default: <b>on</b> <a href="#EGPM">EGPM</a>-devices will be created automatically with a <b>set</b>-command.
      Change this attribute to value <b>off</b> to avoid that mechanism.
    <li><a href="#loglevel">loglevel</a></li>
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
    Das Modul erstellt eine Verbindung zu einer Gembird &reg; <a href="http://energenie.com/item.aspx?id=7557" >Energenie EG-PM2-LAN</a> Steckdosenleiste und steuert 4 angeschlossene Ger&auml;te..
    Falls mehrere Steckdosenleisten &uuml;ber das Netzwerk gesteuert werden, ist es ratsam, diese zuerst &uuml;ber die Web-Oberfl&auml;che zu konfigurieren und die einzelnen Steckdosen zu benennen. Die Namen werden dann automatisch in die
    Oberfl&auml;che von FHEM &uuml;bernommen. Bitte darauf achten, die Weboberfl&auml;che mit <i>Logoff</i> wieder zu verlassen, da der Zugriff sonst blockiert wird.
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
    Wenn das globale Attribut <a href="#autocreate">autocreate</a> aktiviert ist, wird f&uuml;r jede Steckdose ein <a href="#EGPM">EGPM</a>-Eintrag erstellt.<br>
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
    <li>stateDisplay</li>
      Default: <b>socketNumer</b> wechselt zwischen <b>socketNumer</b> und <b>socketName</b> f&uuml;r jeden Statuseintrag. Verwende <b>set statusrequest</b>, um die Anzeige zu aktualisieren.
    <li>autocreate</li>
    Default: <b>on</b> <a href="#EGPM">EGPM</a>-Eintr&auml;ge werden automatisch mit dem <b>set</b>-command erstellt.
    <li><a href="#loglevel">loglevel</a></li>
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
