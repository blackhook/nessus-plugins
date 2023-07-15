#TRUSTED 66514c17060352554c234e01bc2cb126caa43bd0fccb8450b83351ed9647527dafed0350e73bc86027818da40bda9472be3ea2936b53c8e03613c2b3f334234563447b9299922f8dfd8ff9a71026e25069d334122c595e1c4011cc0073d5eb766c66189d145bf58ab9a2ddcad7143e461dc8c3751ce40574930013824c18138e171dbc4f630b42614124d4811b41c2e4495b614336cb4686f106b020fd2469478d14efa235103435606af08153cbaff26dd1903b9bde3609f39851bd481fb8b1a6c822f3d2ef55e15b5fd7f1d931698c39d1975fe802dd384c59ddfae015b954454ad3ae1196ff2ab4d87e5a44f799016fc004431a7aef91a479b1b78ac542ce14e32f62d5229a1491b275eceb4f1d25ee34555afb533248ec44a128bd1c6e88ef04ee97bffd34e783d8c8ba726eb38cb3179c5b263ad0b79ba97857d9cdf0b6b481227392e59d11a82204b62a5c0d7684208cd528675b435d2bc7539dd2285d651ac4643c50d273f044f2c2b183c20edf289d5733db6122ee5ce801b5c50cfecfae831c408cbf1b10e185d76bb2ba8a1849f1f4651cf72000b15fc84abd85732829032cc1ba58656cfc474ff0f8a3dae0ef26530c21719142e2de1ddd1648a3e6cbe8cdc7fb16f0ae61ceb9257846792919fef75d255dab4211fae46ecaee9855fa83e19ff7491bdaa741bce5254ac919216c98dbf91d654d908a4888e57237
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70784);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id(
    "CVE-2013-5543",
    "CVE-2013-5545",
    "CVE-2013-5546",
    "CVE-2013-5547"
  );
  script_bugtraq_id(63436, 63439, 63443, 63444);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtt26470");
  script_xref(name:"CISCO-BUG-ID", value:"CSCud72509");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuf08269");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuh19936");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20131030-asr1000");

  script_name(english:"Multiple Vulnerabilities in Cisco IOS XE Software for 1000 Series Aggregation Services Routers (cisco-sa-20131030-asr1000)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"Cisco IOS XE Software for 1000 Series Aggregation Services Routers
(ASR) contains the following denial of service (DoS) vulnerabilities :

  - Cisco IOS XE Software TCP Segment Reassembly Denial of
    Service Vulnerability (CVE-2013-5543)

  - Cisco IOS XE Software Malformed EoGRE Packet Denial of
    Service Vulnerability (CVE-2013-5545)

  - Cisco IOS XE Software Malformed ICMP Packet Denial of
    Service Vulnerability (CVE-2013-5546)

  - Cisco IOS XE Software PPTP Traffic Denial of Service
    Vulnerability (CVE-2013-5547)

These vulnerabilities are independent of each other. A release that is
affected by one of the vulnerabilities may not be affected by the
others.

Successful exploitation of any of these vulnerabilities allows an
unauthenticated, remote attacker to trigger a reload of the Embedded
Services Processors (ESP) card or the Route Processor (RP) card, which
causes an interruption of services.

Repeated exploitation can result in a sustained DoS condition.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20131030-asr1000
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?91b80ea8");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20131030-asr1000.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/07");

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
cbi = "CSCtt26470";
fixed_ver = "";
temp_flag = 0;
if ((version =~ '^3\\.4[^0-9]') && (cisco_gen_ver_compare(a:version,b:'3.4.2S') == -1)) { fixed_ver = "3.4.2S"; temp_flag++; }
if ((version =~ '^3\\.5[^0-9]') && (cisco_gen_ver_compare(a:version,b:'3.5.1S') == -1)) { fixed_ver = "3.5.1S"; temp_flag++; }

if (get_kb_item("Host/local_checks_enabled"))
{
  if (temp_flag)
  {
    temp_flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_policy-map_type_inspect_zone-pair", "show policy-map type inspect zone-pair");
    if (check_cisco_result(buf))
    {
      if (
           (
             (preg(multiline:TRUE, pattern:"Match: protocol udp", string:buf)) ||
             (preg(multiline:TRUE, pattern:"Match: protocol tcp", string:buf))
            ) &&
           (preg(multiline:TRUE, pattern:"Inspect", string:buf))
         ) { temp_flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
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

cbi = "CSCuh19936";
fixed_ver = "";
temp_flag = 0;
if ((version =~ '^3\\.9[^0-9]') && (cisco_gen_ver_compare(a:version,b:'3.9.2S') == -1)) { fixed_ver = "3.9.2S"; temp_flag++; }

if (get_kb_item("Host/local_checks_enabled"))
{
  if (temp_flag)
  {
    temp_flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (
           (
             (preg(multiline:TRUE, pattern:"ip nat inside", string:buf)) ||
             (preg(multiline:TRUE, pattern:"ip nat outside", string:buf))
            ) &&
           (!preg(multiline:TRUE, pattern:"no ip nat service pptp", string:buf))
         ) { temp_flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
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

cbi = "CSCud72509";
fixed_ver = "";
temp_flag = 0;
if ((version =~ '^3\\.7[^0-9]') && (cisco_gen_ver_compare(a:version,b:'3.7.3S') == -1)) { fixed_ver = "3.7.3S"; temp_flag++; }
if ((version =~ '^3\\.8[^0-9]') && (cisco_gen_ver_compare(a:version,b:'3.8.1S') == -1)) { fixed_ver = "3.8.1S"; temp_flag++; }

if (get_kb_item("Host/local_checks_enabled"))
{
  if (temp_flag)
  {
    temp_flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"ip nat (inside|outside)", string:buf))
      {
        buf = cisco_command_kb_item("Host/Cisco/Config/show_inventory", "show inventory");
        if (check_cisco_result(buf))
        {
          if (preg(multiline:TRUE, pattern:"ASR1000-ESP100", string:buf)) { temp_flag = 1; }
          if (preg(multiline:TRUE, pattern:"ASR1002-X", string:buf)) { temp_flag = 1; }
        } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
      }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
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

cbi = "CSCuf08269";
fixed_ver = "";
temp_flag = 0;
if ((version =~ '^3\\.9[^0-9]') && (cisco_gen_ver_compare(a:version,b:'3.9.2S') == -1)) { fixed_ver = "3.9.2S"; temp_flag++; }

if (get_kb_item("Host/local_checks_enabled"))
{
  if (temp_flag)
  {
    temp_flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"tunnel mode ethernet gre ipv4", string:buf)) { temp_flag = 1; }
      if (preg(multiline:TRUE, pattern:"tunnel mode ethernet gre ipv6", string:buf)) { temp_flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
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
  security_hole(port:0, extra:cisco_caveat());
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
