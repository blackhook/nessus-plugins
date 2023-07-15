#TRUSTED a7cce7a42135a191044d8f7553e58bdb201e8ec2dc0d766049c017673d58abe754b29e3fcc9a264ad0d39444b15c8a1940460a61fb68d3c90bdc2861fe929557c8f405fe16631bc939553f1e6c3402b5eed8ce63e6c510b314812b9746c523b0c1b6c4abe8b0f3c4112f7b6ac4cb25d8b0074172cc551d9467bdd7e0469602195e323dbfa5b9d720bc5324085ba8d957289bbc7c0cdc43f86470d482cf16382e20c79e7865f0a6eb052de9ab0fb830ac6240f32323a8abe6475a2a64a78c5f6125322702b4ca3af191d7c2f5478545e4950afc7fdd941506a0be713c0891f9451821ba4e899587461995bb257338b0d7cb8af7149324b5669d13a24984e0bcd59ac54814496d0952a53795d7fff4946e9f8f8ecf0405668900dbc9f64df364cce39a0dd57704eccfe10925cf12b6a997a42250424e5dd5e2a70b786d2cdb575c7f106e1ce967fd3ee3c4c81b510ff776fbdc61e02806db910403090623bb881c6ce7193e3976863add9c9b6da34ee481036c576422f695631ecf4eb393e1473c4310d644e4846d3897634547428f07cbc7f2ed2f59a1d6545c6a2f87f85644bda7163feca5c6356bb4b7cfcd558b433f68c211b53a13c89a88d198df9e1d4c9bab565e8a1e6b75f789bcace06979b6036ab710fe56cb645ac27cd04ae6f96538dbd9bc62010ab5aa0d2a21c8d8a2fc158ada7debfd6734a0b009d5d54b06fec4
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(67218);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id(
    "CVE-2013-1164",
    "CVE-2013-1165",
    "CVE-2013-1166",
    "CVE-2013-1167",
    "CVE-2013-2779"
  );
  script_bugtraq_id(59003, 59007, 59008, 59009, 59040);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtz97563");
  script_xref(name:"CISCO-BUG-ID", value:"CSCub34945");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtz23293");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuc65609");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtt11558");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130410-asr1000");

  script_name(english:"Multiple Vulnerabilities in Cisco IOS XE Software for 1000 Series Aggregation Services Routers (cisco-sa-20130410-asr1000)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"Cisco IOS XE Software for 1000 Series Aggregation Services Routers
(ASR) contains the following denial of service (DoS) vulnerabilities :

  - Cisco IOS XE Software IPv6 Multicast Traffic Denial of
    Service Vulnerability (CVE-2013-1164)

  - Cisco IOS XE Software L2TP Traffic Denial of Service
    Vulnerability (CVE-2013-1165)

  - Cisco IOS XE Software SIP Traffic Denial of Service
    Vulnerability (CVE-2013-1166)

  - Cisco IOS XE Software Bridge Domain Interface Denial of
    Service Vulnerability (CVE-2013-1167)

  - Cisco IOS XE Software MVPNv6 Traffic Denial of Service
    Vulnerability (CVE-2013-2779)

These vulnerabilities are independent of each other, meaning that a
release that is affected by one of the vulnerabilities may not be
affected by the others.

Successful exploitation of any of these vulnerabilities allows an
unauthenticated, remote attacker to trigger a reload of the Embedded
Services Processors (ESP) card or the Route Processor (RP) card,
causing an interruption of services.

Repeated exploitation could result in a sustained DoS condition.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130410-asr1000
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8ee7b008");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20130410-asr1000.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/10");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2018 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
report_extras = "";
override = 0;
model = "";

# check hardware
if (get_kb_item("Host/local_checks_enabled"))
{
  # this advisory only addresses CISCO ASR 1000 series
  buf = cisco_command_kb_item("Host/Cisco/Config/show_platform", "show platform");
  if (buf)
  {
    match = eregmatch(pattern:"Chassis type:\s+ASR([^ ]+)", string:buf);
    if (!isnull(match)) model = match[1];
  }
}
if (model !~ '^10[0-9][0-9]')
  audit(AUDIT_HOST_NOT, 'ASR 1000 Series');

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

# for each cisco bug id, check version and then individual additional checks
# --------------------------------------------
# Cisco IOS XE Software IPv6 Multicast Traffic Denial of Service Vulnerability
# Cisco IOS XE Software MVPNv6 Traffic Denial of Service Vulnerability

cbi = "CSCtz97563 and CSCub34945";
fixed_ver = "";
temp_flag = 0;
if ((version =~ '^3\\.4[^0-9]') && (cisco_gen_ver_compare(a:version,b:'3.4.5S') == -1)) { fixed_ver = "3.4.5S"; temp_flag++; }
if (version =~ '^3\\.5[^0-9]') { fixed_ver = "migrate to an appropriate extended release"; temp_flag++; }
if (version =~ '^3\\.6[^0-9]') { fixed_ver = "migrate to an appropriate extended release"; temp_flag++; }

if (get_kb_item("Host/local_checks_enabled"))
{
  if (temp_flag)
  {
    temp_flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running_include_ipv6", "show running | include ipv6.(enable|address)");
    if (check_cisco_result(buf))
    {
      if ( (preg(multiline:TRUE, pattern:"ipv6 enable", string:buf)) && (preg(multiline:TRUE, pattern:"ipv6 address", string:buf)) ) { temp_flag = 1; }
	  if (temp_flag)
      {
	    temp_flag = 0;
        buf = cisco_command_kb_item("Host/Cisco/Config/show_inventory", "show inventory");
        if (check_cisco_result(buf))
        {
          if (preg(multiline:TRUE, pattern:"ASR1000-ESP40", string:buf)) { temp_flag = 1; }
          if (preg(multiline:TRUE, pattern:"ASR1000-ESP100", string:buf)) { temp_flag = 1; }
        } else if (cisco_needs_enable(buf)) { temp_flag = 1; override = 1; }
      }
    } else if (cisco_needs_enable(buf)) { temp_flag = 1; override = 1; }
  }
}

if (temp_flag)
{
  report +=
    '\n  Cisco bug ID      : ' + cbi +
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : ' + fixed_ver + '\n';
  flag++;
}

# --------------------------------------------
# Cisco IOS XE Software L2TP Traffic Denial of Service Vulnerability

cbi = "CSCtz23293";
fixed_ver = "";
temp_flag = 0;
if (version =~ '^2[^0-9]') { fixed_ver = "migrate to an appropriate extended release"; temp_flag++; }
if (version =~ '^3\\.1[^0-9]') { fixed_ver = "migrate to an appropriate extended release"; temp_flag++; }
if (version =~ '^3\\.2[^0-9]') { fixed_ver = "migrate to an appropriate extended release"; temp_flag++; }
if (version =~ '^3\\.3[^0-9]') { fixed_ver = "migrate to an appropriate extended release"; temp_flag++; }
if ((version =~ '^3\\.4[^0-9]') && (cisco_gen_ver_compare(a:version,b:'3.4.5S') == -1)) { fixed_ver = "3.4.5S"; temp_flag++; }
if (version =~ '^3\\.5[^0-9]') { fixed_ver = "migrate to an appropriate extended release"; temp_flag++; }
if (version =~ '^3\\.6[^0-9]') { fixed_ver = "migrate to an appropriate extended release"; temp_flag++; }
if ((version =~ '^3\\.7[^0-9]') && (cisco_gen_ver_compare(a:version,b:'3.7.1S') == -1)) { fixed_ver = "3.7.1S"; temp_flag++; }

if (get_kb_item("Host/local_checks_enabled"))
{
  if (temp_flag)
  {
    temp_flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running_include_accept-dialin", "show running | include accept-dialin");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"accept-dialin", string:buf)) { temp_flag = 1; }
      if (temp_flag)
      {
	  	temp_flag = 0;
        buf = cisco_command_kb_item("Host/Cisco/Config/show_running_include_xconnect_l2tpv3", "show running | include xconnect|l2tpv3");
        if (check_cisco_result(buf))
        {
          if ( (preg(multiline:TRUE, pattern:"encapsulation l2tpv3", string:buf)) && (preg(multiline:TRUE, pattern:"xconnect", string:buf)) ) { temp_flag = 1; }
        } else if (cisco_needs_enable(buf)) { temp_flag = 1; override = 1; }
      }
    } else if (cisco_needs_enable(buf)) { temp_flag = 1; override = 1; }
  }
}

if (temp_flag)
{
  report +=
    '\n  Cisco bug ID      : ' + cbi +
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : ' + fixed_ver + '\n';
  flag++;
}

# --------------------------------------------
# Cisco IOS XE Software Bridge Domain Interface Denial of Service Vulnerability

cbi = "CSCtt11558";
fixed_ver = "";
temp_flag = 0;
if (version =~ '^3\\.2[^0-9]') { fixed_ver = "migrate to an appropriate extended release"; temp_flag++; }
if (version =~ '^3\\.3[^0-9]') { fixed_ver = "migrate to an appropriate extended release"; temp_flag++; }
if ((version =~ '^3\\.4[^0-9]') && (cisco_gen_ver_compare(a:version,b:'3.4.2S') == -1)) { fixed_ver = "3.4.2S"; temp_flag++; }
if (version =~ '^3\\.5[^0-9]') { fixed_ver = "migrate to an appropriate extended release"; temp_flag++; }

# this check may result in a False Positive condition
# as it would be impossible to create a check that handles
# 100% of configurations, this is a best effort approach
if (get_kb_item("Host/local_checks_enabled"))
{
  if (temp_flag)
  {
    temp_flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running_include_interface", "show running | section interface");
    if (check_cisco_result(buf))
    {
        if (
             (preg(multiline:TRUE, pattern:"interface[^!]*encapsulation untagged", string:buf)) &&
             (preg(multiline:TRUE, pattern:"interface BDI", string:buf)) &&
             (preg(multiline:TRUE, pattern:"rewrite egress", string:buf)) ) { flag = 1; }
        { temp_flag = 1; }
    } else if (cisco_needs_enable(buf)) { temp_flag = 1; override = 1; }
  }
}

if (temp_flag)
{
  report +=
    '\n  Cisco bug ID      : ' + cbi +
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : ' + fixed_ver + '\n';
  flag++;
}

# --------------------------------------------
# Cisco IOS XE Software SIP Traffic Denial of Service Vulnerability

cbi = "CSCuc65609";
fixed_ver = "";
temp_flag = 0;
if ((version =~ '^3\\.4[^0-9]') && (cisco_gen_ver_compare(a:version,b:'3.4.2S') == -1)) { fixed_ver = "3.4.5S"; temp_flag++; }

if (get_kb_item("Host/local_checks_enabled"))
{
  if (temp_flag)
  {
    temp_flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config_include_ipnatvrf", "show running-config  | include ip (nat | .* vrf .*)");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"\s+ip\s+nat\s+inside", string:buf)) { temp_flag = 1; }
      if (preg(multiline:TRUE, pattern:"\s+ip\s+nat\s+outside", string:buf)) { temp_flag = 1; }
      if (temp_flag)
      {
	    temp_flag = 0;
        buf = cisco_command_kb_item("Host/Cisco/Config/show_running_include_ipnat", "show running | include ip nat");
        if (check_cisco_result(buf))
        {
          if (!preg(multiline:TRUE, pattern:"no ip nat service sip", string:buf)) { temp_flag = 1; }
        } else if (cisco_needs_enable(buf)) { temp_flag = 1; override = 1; }
      }
    } else if (cisco_needs_enable(buf)) { temp_flag = 1; override = 1; }
  }
}

if (temp_flag)
{
  report +=
    '\n  Cisco bug ID      : ' + cbi +
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : ' + fixed_ver + '\n';
  flag++;
}

# --------------------------------------------

if (flag)
{
  security_hole(port:0, extra:report + cisco_caveat());
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
