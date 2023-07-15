#TRUSTED 053f78d8cbed396fd8fa13624285f59786d7498f1abecfed3b3d2b32a3a130b57805fd362e25f3003532f908df389c1aacfbda00b8a5c821dbc05cca590507022f936552bd9a98cc453c17fe4a18f6112b6dd0d133d133d38029547102fac6fee671e21f12cb35aa975aa8d3af6823c1574fcfbd2520cd2c688a63ebe83f20f5fee7273169c12514e7a22417391a80f8cc40f8769c360332400950282cef1e76c6f45feb320e53626be72b4b0b764c7dd44559df90ae43bd2787bbc29d7db23068c131de8da1c8bc6f7c2858221ec777a11a5bdde16748d67566be3c4a1e923751afd855d947ee0a7726d4f01e1fae913cc8bf64baab4225e68dc7b3e788f9db11a7caabbc586e75d50d609b1b564ecb80ff6af82b3fc2a4b2f420fcdba427461d5711958de6625be7ecda9712e2cf0657cff65e769b68ca9bf1f9076cc37fc384d80f3f3eaf53ff4e0801387d302dfa9acbd105757a2b5ef01b16f02b59af3d22a21fd540160368f6522a59696d12dbde7325ec6a3434e8904c5ffdaeef38d63542cdef0ae87fffe217bf6b9225b7853d197882f7090006edea3bc74bc7a10138280bca707db1675f69845222536e98afe82337c8a92d7882a4680efb7befc3a7d888d8cec035b94b793aeceafb64fd29979069941f081cd59ce8e2258cf0e0f5f7a9d4929fd7dbccce799bc23b4dfbeba5afe23949560303c2155e3a06625d
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20120926-c10k-tunnels.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(62371);
  script_version("1.15");
  script_cvs_date("Date: 2019/12/04");

  script_cve_id("CVE-2012-4620");
  script_xref(name:"CISCO-BUG-ID", value:"CSCts66808");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20120926-c10k-tunnels");

  script_name(english:"Cisco IOS Software Tunneled Traffic Queue Wedge Vulnerability (cisco-sa-20120926-c10k-tunnels)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"Cisco IOS Software contains a queue wedge vulnerability that can be
triggered when processing IP tunneled packets. Only Cisco IOS Software
running on the Cisco 10000 Series router has been demonstrated to be
affected. Successful exploitation of this vulnerability may prevent
traffic from transiting the affected interfaces. Cisco has released
free software updates that addresses this vulnerability. There are no
workarounds for this vulnerability.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20120926-c10k-tunnels
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a5eae369");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20120926-c10k-tunnels.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2012-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}



include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;

version = get_kb_item_or_exit("Host/Cisco/IOS/Version");
if ( version == '12.2(33)SB' ) flag++;
if ( version == '12.2(33)SB1' ) flag++;
if ( version == '12.2(33)SB10' ) flag++;
if ( version == '12.2(33)SB11' ) flag++;
if ( version == '12.2(33)SB1a' ) flag++;
if ( version == '12.2(33)SB1b' ) flag++;
if ( version == '12.2(33)SB2' ) flag++;
if ( version == '12.2(33)SB3' ) flag++;
if ( version == '12.2(33)SB4' ) flag++;
if ( version == '12.2(33)SB5' ) flag++;
if ( version == '12.2(33)SB6' ) flag++;
if ( version == '12.2(33)SB6a' ) flag++;
if ( version == '12.2(33)SB6aa' ) flag++;
if ( version == '12.2(33)SB6b' ) flag++;
if ( version == '12.2(33)SB7' ) flag++;
if ( version == '12.2(33)SB8' ) flag++;
if ( version == '12.2(33)SB8b' ) flag++;
if ( version == '12.2(33)SB8c' ) flag++;
if ( version == '12.2(33)SB8d' ) flag++;
if ( version == '12.2(33)SB8e' ) flag++;
if ( version == '12.2(33)SB8f' ) flag++;
if ( version == '12.2(33)SB8g' ) flag++;
if ( version == '12.2(33)SB9' ) flag++;
if ( version == '12.2(33)SRC' ) flag++;
if ( version == '12.2(33)SRC1' ) flag++;
if ( version == '12.2(33)SRD' ) flag++;
if ( version == '12.2(33)XND' ) flag++;
if ( version == '12.2(33)XNE' ) flag++;
if ( version == '12.2(33)XNE1' ) flag++;
if ( version == '12.2(33)XNE2' ) flag++;
if ( version == '12.2(33)XNE3' ) flag++;
if ( version == '12.2(34)SB1' ) flag++;
if ( version == '12.2(34)SB2' ) flag++;
if ( version == '12.2(34)SB3' ) flag++;
if ( version == '12.2(34)SB4' ) flag++;
if ( version == '12.2(34)SB4a' ) flag++;
if ( version == '12.2(34)SB4b' ) flag++;
if ( version == '12.2(34)SB4c' ) flag++;
if ( version == '12.2(34)SB4d' ) flag++;
if ( version == '15.0(1)S' ) flag++;
if ( version == '15.0(1)S1' ) flag++;
if ( version == '15.0(1)S2' ) flag++;
if ( version == '15.0(1)S3a' ) flag++;
if ( version == '15.0(1)S4' ) flag++;
if ( version == '15.0(1)S4a' ) flag++;
if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_interface_brief", "show ip interface brief");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"Tunnel", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}



if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
