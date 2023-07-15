#TRUSTED 7e8a163822e3796941e0d7a3b7142a2c4888f8e6c97d32d7c9ae9aed5fcce50063e071f4385be9080c9ef018b2fddd671f3153e3a14d17afb9874176b3bd94a41ab6288037735abca34f46cbf51ab60dc92284f1c08b2bdec213c25dd81092c0f9b1970b00fd314923e437083d69a7a23723419fa3a6efcc662ec56dfb88e956ef796eb5880b62e2ad91883abe2184943fbeac3a039882523f07e9dbff13e21fc55a7a6a1ec65367d44a51c979bbdcd08061f695ca1ae4b2398887bbccec88ca9500966f9a3a703b8b8a47c63be1b34ff412dbab6c4d18afb90f118083a308ef9b2bb7b9f7eb608c87459fcf7e0338e55b0e82fbb26ee5b11e46dc0b16333b675618d2ca150582ffc90ea9f06f0ef53bbbfeaca604b1dace9e37ee227abf6f81519d7c4f1bdcb826bc1946f40c4de978f0b045d2016f4aefa21d59b46d8f656fbddea336bbe51d5cfa9c91a66e80ade066a9f53e7468b76f5cf898bfbf864d3f6fbe21671c862fc7d6dd985599df586804e8c8446b34ecf1320009e8e7799aff84602cd59419d28275d48f197db86f3eb5b8505081c6abec48d4f96638174233dd3e48d8be43e042ceaf5a3e46bc6a3e06f6f1abf5c9f2e868ca9e0aef16fb389a5c20b4aaac1ab78848e5fedcee91c44c80694c7c537c12250816fcb5d94d3ceef7539dad4fe65bc6a726ffd578b189cdab8584fcb3e217f098c434a7ead662
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78064);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2013-5499");
  script_bugtraq_id(62866);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuh46822");

  script_name(english:"Cisco IOS DHCP Remember Functionality DoS (CSCuh46822)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is running a vulnerable IOS version.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote IOS device is
affected by a denial of service vulnerability when the remember
functionality of DHCP is enabled.

A flaw exists where the remember functionality does not correctly
handle the releasing of leases. An attacker can exploit this issue by
obtaining a lease and then releasing it, which may cause the device to
reload.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=31156");
  # https://tools.cisco.com/security/center/viewAlert.x?alertId=31156
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?21f35e85");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuh46822.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/06");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2018 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version = get_kb_item_or_exit("Host/Cisco/IOS/Version");

flag = 0;
override = 0;

# Check for vuln version
if (version == '15.1GC') flag++;
else if (version == '15.1(4)GC') flag++;
else if (version == '15.1(4)GC1') flag++;
else if (version == '15.1M') flag++;
else if (version == '15.1(4)M') flag++;
else if (version == '15.1(4)M1') flag++;
else if (version == '15.1(4)M2') flag++;
else if (version == '15.1(4)M3') flag++;
else if (version == '15.1(4)M3a') flag++;
else if (version == '15.1(4)M4') flag++;
else if (version == '15.1(4)M5') flag++;
else if (version == '15.1(4)M6') flag++;
else if (version == '15.1(4)M7') flag++;
else if (version == '15.1T') flag++;
else if (version == '15.1(3)T') flag++;
else if (version == '15.1(3)T1') flag++;
else if (version == '15.1(3)T2') flag++;
else if (version == '15.1(3)T3') flag++;
else if (version == '15.1(3)T4') flag++;
else if (version == '15.1XB') flag++;
else if (version == '15.1(4)XB4') flag++;
else if (version == '15.1(4)XB5') flag++;
else if (version == '15.1(4)XB5a') flag++;
else if (version == '15.1(4)XB6') flag++;
else if (version == '15.1(4)XB7') flag++;
else if (version == '15.1(4)XB8') flag++;
else if (version == '15.1(4)XB8a') flag++;
else if (version == '15.2GC') flag++;
else if (version == '15.2(1)GC') flag++;
else if (version == '15.2(1)GC1') flag++;
else if (version == '15.2(1)GC2') flag++;
else if (version == '15.2(2)GC') flag++;
else if (version == '15.2(3)GC') flag++;
else if (version == '15.2(3)GC1') flag++;
else if (version == '15.2(4)GC') flag++;
else if (version == '15.2GCA') flag++;
else if (version == '15.2(3)GCA') flag++;
else if (version == '15.2(3)GCA1') flag++;

# Check for DHCP remember functionality enabled
if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag > 0)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"ip dhcp remember", string:buf)) flag = 1;
    }
    else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag > 0)
{
  if(report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCuh46822' +
      '\n  Installed release : ' + version +
      '\n';
    security_warning(port:0, extra:report + cisco_caveat(override));
  }
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
