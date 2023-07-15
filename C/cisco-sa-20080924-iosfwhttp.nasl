#TRUSTED 663d68cfc5da8bb3343b39354f62ad08bb991c374e8270de71776326935bd2a22b966e79ca3b03e6a7ea4fd9ea6bdd2abf7e425bcb436fbcf8985c70608a2817916dd3056f567bc99a6994cea333997366310b4de743cfbc0eefc4f4e3b7412266ca3f38f8e548af95d24b6afc1ded62216f0619854305d2946515992ee8fe642b50b15c0405202ce4784ea859b576b04cfd5582f275320ec985f0fac818d0e04395677b0d778df0e9b00855c8c01b41cf20f61a5d07b374f9478caf60b17cf522ec025bb4ca5631d7507c92a51866e8a8dd67036e9c730f029dacb14f330247ab372f3ddbd5f8bd5a217a8406c572e17a97596bf02f79afd671d8294376a85545ab8e3c143987d55a02494095496cfbee9a26b2ea435c44a07a87d8749c6913cc48fc905f978a7a7c6daf86f375438f2252d26a65d7736e95ebbe4b4f265d839661016a53760e68098cdd34b9e8af7bcfe421580ea63ad6b5eaa48e67e420ef1b2853dc0d9af42733e97ae060d52416f05310b57ef0cda372548b46178f4dff50f5c944bcbc7418bebc51098238b2c53688ff711f392bd0a513ad1d491ae977ed0d65773ad86c9a41ff18ed37eab9181b849b90f6356401338d282b2e4b5f26eaa785815338f218492c1ad1c4a064a7f3b51f637cb1af5d14b956520c3bf640fa9a8ece694c54927aa00427b2a6f2fde856c60c4f808fba25c86ecad30ae535
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See https://www.cisco.com/en/US/products/products_security_advisory09186a0080a01545.shtml

include("compat.inc");

if (description)
{
 script_id(49018);
 script_version("1.22");
 script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

 script_cve_id("CVE-2008-3812");
 script_bugtraq_id(31354);
 script_xref(name:"CISCO-BUG-ID", value:"CSCsh12480");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20080924-iosfw");

 script_name(english:"Cisco IOS Software Firewall Application Inspection Control Vulnerability");
 script_summary(english:"Checks IOS version");

 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
"Cisco IOS software configured for IOS firewall Application Inspection
Control (AIC) with a HTTP configured, application-specific policy are
vulnerable to a denial of service when processing a specific, malformed
HTTP transit packet.  Successful exploitation of the vulnerability may
result in a reload of the affected device.

Cisco has released free software updates that address this
vulnerability.

A mitigation for this vulnerability is available. See the 'Workarounds'
section for details.");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a1bf1ebf");
 # https://www.cisco.com/en/US/products/products_security_advisory09186a0080a01545.shtml
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5e551fd3");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20080924-iosfw.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(20);

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/09/24");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/09/24");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is (C) 2010-2018 Tenable Network Security, Inc.");
 script_family(english:"CISCO");

 script_dependencie("cisco_ios_version.nasl");
 script_require_keys("Host/Cisco/IOS/Version");
 exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;
version = get_kb_item_or_exit("Host/Cisco/IOS/Version");

if (version == '12.4(11)XW') flag++;
else if (version == '12.4(11)XV1') flag++;
else if (version == '12.4(11)XV') flag++;
else if (version == '12.4(14)XK') flag++;
else if (version == '12.4(11)XJ4') flag++;
else if (version == '12.4(11)XJ3') flag++;
else if (version == '12.4(11)XJ2') flag++;
else if (version == '12.4(11)XJ') flag++;
else if (version == '12.4(6)XE3') flag++;
else if (version == '12.4(6)XE2') flag++;
else if (version == '12.4(6)XE1') flag++;
else if (version == '12.4(6)XE') flag++;
else if (version == '12.4(11)T3') flag++;
else if (version == '12.4(11)T2') flag++;
else if (version == '12.4(11)T1') flag++;
else if (version == '12.4(11)T') flag++;
else if (version == '12.4(9)T6') flag++;
else if (version == '12.4(9)T5') flag++;
else if (version == '12.4(9)T4') flag++;
else if (version == '12.4(9)T3') flag++;
else if (version == '12.4(9)T2') flag++;
else if (version == '12.4(9)T1') flag++;
else if (version == '12.4(9)T') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_policy-map_type_inspect_zone-pair", "show policy-map type inspect zone-pair");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"Policy: http layer7-policymap", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
