###
# (C) Tenable Network Security, Inc.
###

include("compat.inc");

if (description)
{
  script_id(50542);
  script_version("1.24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/12");

  script_name(english:"OS Identification : SIP");
  script_summary(english:"Identifies devices based on its SIP banner");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to identify the remote operating system based on its
SIP banner.");
  script_set_attribute(attribute:"description", value:
"The remote operating system can be identified through the banner
reported by a SIP service running on it.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"os_identification", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2010-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sip_detection.nasl");
  script_require_ports("Services/udp/sip", "Services/sip");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

##
# sip detection list.
#
# @remark _g_sip_detect_list ensures a plugin only needs to load the
# known sip detection list one time per invocation.
#
# @remark _g_sip_detect_list is internal and should not be utilized
# instead call sip_detections to get the list.
#
##
var _g_osfp_sip_detect_list = NULL;

##
# Create a sip detection array.
#
# @param [name:string] The name associated with the detection.
# @param [pattern:string] A regex used to detect.
# @param [confidence:integer] An optional confidence value 0 to 100.
# @param [type:string] An optional string providing the device type.
# @param [www:string] An optional string providing a web site for vendor.
#
# @return [array] A detection array ready for insertion into
# detection list, capabale of being utilized in detection activities.
##
function _osfp_sip_create_detection( name, pattern, confidence, type, www )
{
  local_var DEFAULT_SIP_CONFIDENCE = 95;
  local_var DEFAULT_WWW = "www.tenable.com";
  local_var DEFAULT_TYPE = "embedded";
  if ( isnull( confidence ) )
  {
    confidence = DEFAULT_SIP_CONFIDENCE;
  }
  if ( isnull( www ) )
  {
    www = DEFAULT_WWW;
  }
  if ( isnull( type ) )
  {
    type = DEFAULT_TYPE;
  }
  return make_array(
    "name", name,
    "pattern", pattern,
    "confidence", confidence,
    "www", www,
    "type", type );
}

##
# Obtain the list of known sip detections.
#
# @remark Every SIP user agent (phone, software, device) identifies
# itself with a string. The syntax of this string is not defined, but
# a common practice is "vendor" "product" "firmware version"
#
# @remark Each detection list item is an array with keys created by
# [_osfp_sip_create_detection].
#
# @remark The pattern key is used by [_osfp_sip_match] for testing
# if a match exist.
#
# @return [list] A list of known sip detections.
##
function _osfp_sip_detections( )
{
  if ( isnull(_g_osfp_sip_detect_list) )
  {
    local_var _g_osfp_sip_detect_list = make_list2(
      # put more valued patterns early in list
      # use hat ^ or whitespace matching to protect short patterns
      _osfp_sip_create_detection( name:"3CX", pattern:"^3CX", www:"3cx.com" ),
      _osfp_sip_create_detection( name:"Mitel", pattern:"Aastra", www:"www.mitel.com" ),
      _osfp_sip_create_detection( name:"Cisco", pattern:"Acano", www:"www.acano.com" ),
      _osfp_sip_create_detection( name:"ADTRAN", pattern:"ADTRAN", www:"www.adtran.com" ),
      _osfp_sip_create_detection( name:"Alcatel-Lucent", pattern:"OmiPCX", www:"networks.nokia.com" ),
      _osfp_sip_create_detection( name:"Alcatel-Lucent", pattern:"OmniPCX", www:"networks.nokia.com" ),
      _osfp_sip_create_detection( name:"AudioCodes", pattern:"AudioCodes", www:"www.audiocodes.com" ),
      _osfp_sip_create_detection( name:"Avaya", pattern:"Avaya", www:"www.avaya.com" ),
      _osfp_sip_create_detection( name:"Cisco", pattern:"Cisco", www:"www.cisco.com" ),
      _osfp_sip_create_detection( name:"CommuniGate Systems", pattern:"CommuniGate", www:"www.communigate.com" ),
      _osfp_sip_create_detection( name:"CoreDial", pattern:"CoreDialPBX", www:"www.coredial.com" ),
      _osfp_sip_create_detection( name:"Digium", pattern:"Digium", www:"www.digium.com" ),
      _osfp_sip_create_detection( name:"FreePBX", pattern:"FreePBX", www:"www.freepbx.org" ),
      _osfp_sip_create_detection( name:"FreePBX", pattern:"FPBX", www:"www.freepbx.org" ),
      _osfp_sip_create_detection( name:"FreeSWITCH", pattern:"FreeSWITCH", www:"www.freeswitch.org" ),
      _osfp_sip_create_detection( name:"Gigaset", pattern:"N300", www:"www.gigaset.com" ),
      _osfp_sip_create_detection( name:"Lifesize", pattern:"Lifesize", www:"www.lifesize.com" ),
      _osfp_sip_create_detection( name:"Linksys", pattern:"Linksys", www:"www.linksys.com" ),
      _osfp_sip_create_detection( name:"Mediatrix", pattern:"Mediatrix", www:"www.media5corp.com" ),
      _osfp_sip_create_detection( name:"Mitel", pattern:"Mitel", www:"www.mitel.com" ),
      _osfp_sip_create_detection( name:"NEC", pattern:"^NEC(\-i)?", www:"www.necam.com" ),
      _osfp_sip_create_detection( name:"Polycom", pattern:"Polycom", www:"www.polycom.com" ),
      _osfp_sip_create_detection( name:"Microsoft", pattern:"RTC", www:"www.microsoft.com" ),
      _osfp_sip_create_detection( name:"Mitel", pattern:"ShoreGear", www:"www.mitel.com" ),
      _osfp_sip_create_detection( name:"Ingate", pattern:"SIParator", www:"www.ingate.com" ),
      _osfp_sip_create_detection( name:"Cisco", pattern:"Sipura", www:"www.cisco.com" ),
      _osfp_sip_create_detection( name:"Cisco", pattern:"TANDBERG", www:"www.cisco.com" ),
      _osfp_sip_create_detection( name:"Biamp", pattern:"Tesira", www:"www.biamp.com" ),
      _osfp_sip_create_detection( name:"Twilio", pattern:"Twilio", www:"www.twilio.com" ),
      _osfp_sip_create_detection( name:"Uniview", pattern:"VCP MWARE", www:"www.uniview.com" ),
      _osfp_sip_create_detection( name:"Yealink", pattern:"Yealink", www:"www.yealink.com" ),
      _osfp_sip_create_detection( name:"Zultys", pattern:"Zultys", www:"www.zultys.com" ),
      _osfp_sip_create_detection( name:"ZyXEL", pattern:"ZyXEL", www:"www.zyxel.com" ),

      # from shodan w/ no telemetry
      _osfp_sip_create_detection( name:"DrayTek", pattern:"draytek", www:"www.draytek.com" ),
      _osfp_sip_create_detection( name:"D-Link", pattern:"d-?link", www:"us.dlink.com" ),
      _osfp_sip_create_detection( name:"Telekom", pattern:"Speedport", www:"www.telekom.de" ),
      _osfp_sip_create_detection( name:"Grandstream", pattern:"Grandstream", www:"www.grandstream.com" ),
      _osfp_sip_create_detection( name:"AVM", pattern:"FRITZ!", www:"en.avm.de" ),
      _osfp_sip_create_detection( name:"Technicolor", pattern:"TG7[0-9]{2}", www:"www.technicolor.com" ),
      _osfp_sip_create_detection( name:"Snom", pattern:"snom", www:"www.snom.com" ),
      _osfp_sip_create_detection( name:"Sagemcom", pattern:"Sagem", www:"www.sagemcom.com" ),
      _osfp_sip_create_detection( name:"Billion", pattern:"BiPAC", www:"au.billion.com" ),
      _osfp_sip_create_detection( name:"Arris", pattern:"Arris", www:"www.arris.com" ),
      _osfp_sip_create_detection( name:"Gigaset", pattern:"A[0-9][0-9][0-9]A? ?IP", www:"www.gigaset.com" ),
      _osfp_sip_create_detection( name:"Gigaset", pattern:"C[0-9][0-9][0-9]A? ?IP", www:"www.gigaset.com" ),
      _osfp_sip_create_detection( name:"Ericsson-LG", pattern:"iPECS", www:"www.ipecs.com" ),
      _osfp_sip_create_detection( name:"Ericsson-LG", pattern:"LG-Ericsson", www:"www.ipecs.com" ),
      _osfp_sip_create_detection( name:"Ericsson-LG", pattern:"Ericsson-LG", www:"www.ipecs.com" ),
      _osfp_sip_create_detection( name:"Fortinet", pattern:"FortiVoice", www:"www.fortinet.com" ),

      # more generic patterns
      _osfp_sip_create_detection( name:"OpenSIPStack", pattern:"OpenSIP", www:"www.opensipstack.org" ),
      _osfp_sip_create_detection( name:"Asterisk", pattern:"Asterisk", www:"www.asterisk.org" )
    );
  }
  return _g_osfp_sip_detect_list;
}

##
# Uses sip detection list to decide if the specified sip string matches.
#
# @param [sip:string] The sip string to test.
#
# @remark Specified sip string matched based on "pattern" key.
#
# @remark Search for a match ends after the first match is found.
#
# @return [array] NULL when no match exist, if a match is made then
# array contains keys for name, confidence, www, and matched. Where
# name is the Tenable assigned name, confidence is a confidence for
# comparing detection methods, www is a vendor website, and matched
# is the sip string itself.
##
function _osfp_sip_match( sip )
{
  # param needed to make a match
  if ( isnull( sip ) )
  {
    # no param, no match
    return NULL;
  }
  # look thru entire detection list for first match
  local_var res = NULL;
  local_var d;
  foreach d ( _osfp_sip_detections( ) )
  {
    # does this detection match?
    if ( preg( pattern:d["pattern"], string:sip, icase:TRUE ) )
    {
      # match, create result array w/ appropriate keys
      res = make_array(
        "name", d["name"],
        "confidence", d["confidence"],
        "www", d["www"],
        "type", d["type"],
        "match", sip
      );
      return res;
    }
    # no match, move to next detection
  }
  return NULL;
}

##
# Check the sip banner against detections.
#
# @param [banner:string] The sip banner to test.
#
# @return [bool] TRUE if a match is found, otherwise FALSE.
##
function check_banner( banner )
{
  set_kb_item( name:"Host/OS/SIP/Fingerprint", value:banner );
  local_var match = _osfp_sip_match( sip: banner );
  if ( !isnull( match ) )
  {
    set_kb_item( name:"Host/OS/SIP", value: match["name"] + ' SIP Device' );
    set_kb_item( name:"Host/OS/SIP/Confidence", value:match["confidence"] );
    set_kb_item( name:"Host/OS/SIP/Type", value: match["type"] );
    return TRUE;
  }
  return FALSE;
}

# are we running unit tests?
global_var osfp_dont_exit;
if ( isnull( osfp_dont_exit ) )
{
  # not unit tests, the real thing
  var udp_ports = get_kb_list( "Services/udp/sip" );
  var tcp_ports = get_kb_list( "Services/sip" );

  if ( empty_or_null( udp_ports ) && empty_or_null( tcp_ports ) )
  {
    audit(AUDIT_HOST_NONE, "SIP services");
  }

  if ( !empty_or_null( udp_ports ) )
  {
    foreach var port ( make_list( udp_ports ) )
    {
      var banner = get_kb_item( "sip/banner/udp/" + port );
      if ( empty_or_null( banner ) )
      {
        continue;
      }
      if ( check_banner( banner:banner ) )
      {
        exit(0, "Found matching SIP device on port " + port );
      }
    }
  }
  if ( !empty_or_null( tcp_ports ) )
  {
    foreach port ( make_list( tcp_ports ) )
    {
      banner = get_kb_item( "sip/banner/" + port );
      if ( empty_or_null( banner ) )
      {
        continue;
      }
      if ( check_banner( banner:banner ) )
      {
        exit(0, "Found matching SIP device on port " + port );
      }
    }
  }
  exit(0, "Nessus was not able to identify the OS from a SIP service banner.");
}
