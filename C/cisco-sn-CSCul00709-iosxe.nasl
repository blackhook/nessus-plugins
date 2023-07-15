#TRUSTED 3ee45fb7db99b10dd8ea141f39a8c58f1eeea83851c7dff182a1dd6cbca71cc46fe4a30375b0d640f833eda58f5335f6271d1174c4cefd10554184ec1cb9ea292ff16534a86cb408c7a8c7ef881da365bed501ab04a060fd60ec5b874512622bf16f80613480caa2c6566205af0e23a161e1e20121a25b3ce240b44fd76a86627d7c97e2564d898d3ad9b16b0d52908d86dae5b59d82726d504c6ed619c19381eda15d460a570de79ab67131b98585f4bfc51a8375588c6e96df9383f81fd7a6e893c27e1e9139ca59b425e5bd43ff6326991747288f7d4d691d5139b15d2e6ee24f2ea5a9828f5dc33db26a4a6ea0074246f1992840a4e5eb9f6a32aed8ba05c420a7d21603c465a5c648011038572b1f975f325f554f1dc34d62a5411027c65303ad04da999a223f85714311dfcbe3145837aac0b6c82fc94eaa011befa1ef7e270343e821c8ec8769254528d5b5e984c4b36e853a22c3906e387a651f13e6dfbf225957fede118bee5aade013552f54e41c5c389dbaf3e544517dd9641f5abb13e81e4373408721f42b66ba1bc3555cb53c1168f8f27550673b72568360837612bfd94b5b297f2e6e4c88246ff5550d225366e3d868d34814e9c7cbcb560f26d0498e6f18bafe71fe9a6d7eff4e6f2f29b1b571b30d1ba1ba3c50be724514b191d4189f59e301aee544b7a95ae81b5dad5b54ae0ceb95a0c1f7331d509bd3
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79146);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2013-6981");
  script_bugtraq_id(64514);
  script_xref(name:"CISCO-BUG-ID", value:"CSCul00709");

  script_name(english:"Cisco IOS XE Crafted MPLS IP Fragmentation DoS (CSCul00709)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is running a vulnerable IOS XE version.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote IOS XE device is
affected by a denial of service vulnerability.

A denial of service flaw exists the Multiprotocol Label Switching
(MPLS) IP fragmentation function of Cisco XE. An unauthenticated,
remote attacker with a specially crafted MPLS IP packet can cause the
Cisco Packet Processor to crash.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=32281");
  # https://tools.cisco.com/security/center/viewAlert.x?alertId=32281
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?be4c182a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCul00709.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/12");

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

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");
model   = get_kb_item_or_exit("Host/Cisco/IOS-XE/Model");
if (model !~ '^ASR 1[0-9][0-9][0-9]($|[^0-9])') audit(AUDIT_HOST_NOT, 'ASR 1000 Series');

flag = 0;
override = 0;

if (version =~ "^2\.5\.0$") flag++;
else if (version =~ "^2\.6\.[0-2]$") flag++;
else if (version =~ "^3\.1\.[0-3]S$") flag++;
else if (version =~ "^3\.2\.[0-2]S$") flag++;
else if (version =~ "^3\.3\.[0-2]S$") flag++;
else if (version =~ "^3\.4\.[0-6]S$") flag++;
else if (version =~ "^3\.5\.[0-2]S$") flag++;
else if (version =~ "^3\.6\.[0-2]S$") flag++;
else if (version =~ "^3\.7\.[0-1]S$") flag++;

if (get_kb_item("Host/local_checks_enabled") && flag > 0)
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"mpls ip", string:buf)) flag = 1;
  } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
}

if (flag > 0)
{
  if (report_verbosity > 0)
  {
    report =
    '\n  Cisco bug ID      : CSCul00709' +
    '\n  Installed release : ' + version +
    '\n';
    security_warning(port:0, extra:report + cisco_caveat(override));
  }
  else security_warning(port:0, extra:cisco_caveat(override));
}
else audit(AUDIT_HOST_NOT, "affected");
