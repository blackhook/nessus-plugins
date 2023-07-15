#TRUSTED 6e3e0c92906ce48d1b147b078c8db7791380805f0fe93c6f197ccdec2dc27acd4753f57bc83a9327e8f2e0a77f400f4d64b2922fdb361a94f8b3c78243e2219f0d1b1646e4e3ed815a2d4cc4c3e03db69673857d1fb282ed3c5a48cbe406e5dae8163d92fc37e51b352d8cb6fcf3a15f1cd9c67968da9be73d090d1b080df52c4af0b13ddf6ec456d6735399fdf862e37135d7decaf352483bcab070da4e6502818cd291e59102f580047f3aa7858952f11f5fc16bd4049455083348742528e24d9316d8f6d834443dc99f650dca9a9a64608c45dba607746024dc375c2c712731fb3cfb8e402e0f82b242ec6bbaf0570b7ad1f0bda7c0cae590af35cf0fc983686eb3a11c9695581174786a46d180ec006b4370dd6822f605c53576eeb1efb0e979ab7623c87b6848f76961b7dc37577ed4e0c1609f84f2659732a9c61630f02ac2021e1d59df7a11553641f87bd0d983e5ffbf4fe85afc81ef71b70cfc243773d7611bc86bd704ff0720c38beb5ad770b9b974f5762cca087b0ff42cfbf9a3dedb5cf7aefac6245353250bee4c4ade54362dcaf7ca26144b0c799a39cd2685056608a012d1c59d6dd9480a01d7a238264aa059d0e392f83ea54be7f08fa33c2c62a9938b396798b785349be587ccdce31be933fae9e726334ea87e8fe7567aa5b2e5d301cb362f1c2838dcaf09bbdde40da116f2cf988d10dbfcf5a39f1a15
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94109);
  script_version("1.10");
  script_cvs_date("Date: 2019/11/14");

  script_cve_id("CVE-2016-1453");
  script_bugtraq_id(93409);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuy95701");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20161005-otv");

  script_name(english:"Cisco NX-OS OTV GRE Packet Header Parameter Handling RCE (cisco-sa-20161005-otv)");
  script_summary(english:"Checks the NX-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version and configuration, the Cisco NX-OS software
running on the remote device is affected by a remote code execution
vulnerability in the Overlay Transport Virtualization (OTV) generic
routing encapsulation (GRE) feature due to improper validation of the
size of OTV packet header parameters. An unauthenticated, remote
attacker can exploit this, via long parameters in a packet header, to
cause a denial of service condition or the execution of arbitrary
code.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161005-otv
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c3d6721f");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuy95701");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco advisory
cisco-sa-20161005-otv. Alternatively, as a workaround, configure an
Access Control List (ACL) to drop malformed OTV control packets.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/18");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Device", "Host/Cisco/NX-OS/Model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

device  = get_kb_item_or_exit("Host/Cisco/NX-OS/Device");
model   = get_kb_item_or_exit("Host/Cisco/NX-OS/Model");
if (device != 'Nexus' || (model !~ '^7[07]{1}[0-9][0-9]([^0-9]|$)'))
  audit(AUDIT_HOST_NOT, "Nexus model 7000 / 7700");

version = get_kb_item_or_exit("Host/Cisco/NX-OS/Version");
flag = FALSE;

if ( version == "4.1(2)" ) flag = TRUE;
if ( version == "4.1(3)" ) flag = TRUE;
if ( version == "4.1(4)" ) flag = TRUE;
if ( version == "4.1(5)" ) flag = TRUE;
if ( version == "4.2(2a)" ) flag = TRUE;
if ( version == "4.2(3)" ) flag = TRUE;
if ( version == "4.2(4)" ) flag = TRUE;
if ( version == "4.2(6)" ) flag = TRUE;
if ( version == "4.2(8)" ) flag = TRUE;
if ( version == "5.0(2a)" ) flag = TRUE;
if ( version == "5.0(3)" ) flag = TRUE;
if ( version == "5.0(5)" ) flag = TRUE;
if ( version == "5.1(1)" ) flag = TRUE;
if ( version == "5.1(1a)" ) flag = TRUE;
if ( version == "5.1(3)" ) flag = TRUE;
if ( version == "5.1(4)" ) flag = TRUE;
if ( version == "5.1(5)" ) flag = TRUE;
if ( version == "5.1(6)" ) flag = TRUE;
if ( version == "5.2(1)" ) flag = TRUE;
if ( version == "5.2(3a)" ) flag = TRUE;
if ( version == "5.2(4)" ) flag = TRUE;
if ( version == "5.2(5)" ) flag = TRUE;
if ( version == "5.2(7)" ) flag = TRUE;
if ( version == "5.2(9)" ) flag = TRUE;
if ( version == "6.0(1)" ) flag = TRUE;
if ( version == "6.0(2)" ) flag = TRUE;
if ( version == "6.0(3)" ) flag = TRUE;
if ( version == "6.0(4)" ) flag = TRUE;
if ( version == "6.1(1)" ) flag = TRUE;
if ( version == "6.1(2)" ) flag = TRUE;
if ( version == "6.1(3)" ) flag = TRUE;
if ( version == "6.1(4)" ) flag = TRUE;
if ( version == "6.1(4a)" ) flag = TRUE;
if ( version == "6.1(5)" ) flag = TRUE;
if ( version == "6.2(2)" ) flag = TRUE;
if ( version == "6.2(2a)" ) flag = TRUE;
if ( version == "6.2(6)" ) flag = TRUE;
if ( version == "6.2(6b)" ) flag = TRUE;
if ( version == "6.2(8)" ) flag = TRUE;
if ( version == "6.2(8a)" ) flag = TRUE;
if ( version == "6.2(8b)" ) flag = TRUE;
if ( version == "6.2(10)" ) flag = TRUE;
if ( version == "6.2(12)" ) flag = TRUE;
if ( version == "6.2(14)" ) flag = TRUE;
if ( version == "6.2(14)S1" ) flag = TRUE;
if ( version == "7.2(0)N1(0.1)" ) flag = TRUE;
if ( version == "7.3(0)D1(1)" ) flag = TRUE;

if (!flag) audit(AUDIT_INST_VER_NOT_VULN, "Cisco NX-OS software", version);

if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;

  # Check for OTV feature
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"^(\s+)?(feature otv|otv join-interface)", string:buf))
    flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;
}

if (flag || override)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_HOLE,
    override : override,
    version  : version,
    bug_id   : 'CSCuy95701',
    cmds     : make_list('show running-config')
  );
} else audit(AUDIT_HOST_NOT, "affected");
