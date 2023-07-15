#TRUSTED 8c7a3289ea505b3d9a1fc0b31d52035131e9cad7663e593090d6cac1343e65c359a402ba6413dd73c8aaea57e51059ec031824b1a21a000de110771d10756003358251121e7993ce332ee54773446902e9ae31d14ecb852abf712b77f05c0a5594b517dc543942bce9f8f49d6804df67401d48584fb22babb5ccc68bab9e24b6d70fc500fb668046ee3a7f17a59bed14ac80ed0ffba7c721e111a87873b5853c11418aa3bf807510b9ef245ac33769766e12b9268957e350d8fed86289adbab36cb5f37a5a4e24fd2d88f65418287fce88f988336be2b9af4f589a72b751fef036a421492e31fcb30bcd09e131bcf4f5886048f89f189d63435202a9f9e676728cf3d2e7744dd14c0d6e528c4fba0b64e5f07d2a57aac8e02e18a94ff2dd90297e88877e12be41d291f8e9382ef51e3cb5e9d7a99d10d205865aeea6700b7eccdb8f2c20fb5d930243ecd2c674d468007c0247134bbb1d97af83f0e987653a1ce100b325bbbf7caf386360e1608df264c8fb6530415b54a04f8abf698dbec25a30b207d2fa28a8b43d0d17b7bfe9c09fe5aeb05257df250154ad23b56702a6f02c3c6dee897a4fc6c8a560000b5880cbf6260355724b325fe3c28a93d2a7e568c2e3645e6a3735af01efa86ad8766ba96f4ee1297142c0a6d0f3be3092d9ac89f13133451a7c9ce693b3108036f3a9c84d2bb4993f84f1421399ce1b8dde03b5
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90308);
  script_version("1.12");
  script_cvs_date("Date: 2019/11/19");

  script_cve_id("CVE-2016-1351");
  script_bugtraq_id(85309);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuv11993");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160323-lisp");

  script_name(english:"Cisco NX-OS Malformed LISP Packet DoS (CSCuv11993)");
  script_summary(english:"Checks the NX-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco NX-OS software running on the remote device is
affected by a denial of service vulnerability in the implementation of
the Locator/ID Separation Protocol (LISP) due to improper input
validation when a malformed LISP packet is received. An
unauthenticated, remote attacker can exploit this, via a crafted
packet, to cause the device to reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160323-lisp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c3df085d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuv11993.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/01");

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
cmds = make_list();

if (
  version == "4.1.(2)" ||
  version == "4.1.(3)" ||
  version == "4.1.(4)" ||
  version == "4.1.(5)" ||
  version == "4.2(3)" ||
  version == "4.2(4)" ||
  version == "4.2(6)" ||
  version == "4.2(8)" ||
  version == "4.2.(2a)" ||
  version == "5.0(2a)" ||
  version == "5.0(3)" ||
  version == "5.0(5)" ||
  version == "5.1(1)" ||
  version == "5.1(1a)" ||
  version == "5.1(3)" ||
  version == "5.1(4)" ||
  version == "5.1(5)" ||
  version == "5.1(6)" ||
  version == "5.2(1)" ||
  version == "5.2(3a)" ||
  version == "5.2(4)" ||
  version == "5.2(5)" ||
  version == "5.2(7)" ||
  version == "5.2(9)" ||
  version == "6.0(1)" ||
  version == "6.0(2)" ||
  version == "6.0(3)" ||
  version == "6.0(4)" ||
  version == "6.1(1)" ||
  version == "6.1(2)" ||
  version == "6.1(3)" ||
  version == "6.1(4)" ||
  version == "6.1(4a)" ||
  version == "6.2(10)" ||
  version == "6.2(12)" ||
  version == "6.2(14)S1" ||
  version == "6.2(2)" ||
  version == "6.2(2a)" ||
  version == "6.2(6)" ||
  version == "6.2(6b)" ||
  version == "6.2(8)" ||
  version == "6.2(8a)" ||
  version == "6.2(8b)" ||
  version == "7.2(0)N1(0.1)"
)
{
  flag     = FALSE;
  override = FALSE;

  if (get_kb_item("Host/local_checks_enabled"))
  {
    # Check for M1 modules
    buf = cisco_command_kb_item("Host/Cisco/Config/show_module_m1", "show module | include M1");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"powered-up(\s|$)", string:buf))
      {
        flag = TRUE;
        cmds = make_list(cmds, "show module | include M1");
      }
    }
    else if (cisco_needs_enable(buf)) override = TRUE;
  }
  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected");
  # Check for LISP enabled
  if (flag || override)
  {
    flag = FALSE;
    override = FALSE;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_feature_lisp", "show feature | include lisp");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"enabled(\s|$)", string:buf))
      {
        flag = TRUE;
        cmds = make_list(cmds, "show feature | include lisp");
      }
    }
    else if (cisco_needs_enable(buf)) override = TRUE;
  }
  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected");
  # Check for LISP on interfaces
  if (flag || override)
  {
    flag = FALSE;
    override = FALSE;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_lisp", "show ip lisp");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"enabled(\s|$)", string:buf))
      {
        flag = TRUE;
        cmds = make_list(cmds, "show ip lisp");
      }
    }
    else if (cisco_needs_enable(buf)) override = TRUE;
  }
  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected");

  security_report_cisco(
    port     : 0,
    severity : SECURITY_HOLE,
    override : override,
    version  : version,
    bug_id   : "CSCuv11993",
    cmds     : cmds
  );
}
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco NX-OS software", version);
