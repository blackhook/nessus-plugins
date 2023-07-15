#TRUSTED 3f53b5123d7ece5d771a3530686e6b243b0629c110b72166de0e2c70e6b47da30d0cafd4b0145ea6fa6f35e843922171c71479002ed13d0fb897a776f338d3c46fb1c290b0dda3973eb35a43d7f35fca5f39766b1968b8b5abfaa50d1ef51904e4f4cb202082f6d07ce5cf68716a1e356c6259fd44ac20a2ad21166e3e605dcba0d22346f2325904d770704a689bff0f3c648bdd96ea381a9003d514a15dedacef3b26e0486edd860bfcd350e8516437ffa2ca97d07864ca54806d6a822ff95ba86cebc6d742ea5689bd238b8d2c464c68b0f963ecb0511696809d4d7c0785879f31c91bbb92e70540efb677f89171d878cd0d357b02c726fbb71366d5af4d145ad4f34f77980e3deb11d1a95d5fbe76e7549404fc180c3d800e3e73a3ee9dafedaf59dc4f85d1c6a91828f2f52bea4ddc1fbe0fe13138a50121bed3b5a9d7e880c6925947ca7659e7c4f53e7d318ad93cec0f9dff8b0e81604e291bdd31e312f960bd5fe7c615c62833942d30243af0a082c2eaade004bf43875aa4a409469cfad3d4c6d0288b74209d68a906f631dd754c47a2d0fb04bb9f8030c90d934d844fcf43a986d84d5b80b843378fad62c4443fc09c6826b4127034defbfce2cdb331be0e5ecf6b589f931d650c6ba52ae0d1feb16ef9a8a099d299531c01d0b7f77aa162583ef98270d25573ae4a50e69e5042f48156d5c77dbf6225b6530d44e0
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20110928-smart-install.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(56320);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2011-3271");
  script_bugtraq_id(49828);
  script_xref(name:"CISCO-BUG-ID", value:"CSCto10165");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20110928-smart-install");

  script_name(english:"Cisco IOS Software Smart Install Remote Code Execution Vulnerability (cisco-sa-20110928-smart-install)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"A vulnerability exists in the Smart Install feature of Cisco Catalyst
Switches running Cisco IOS Software that could allow an
unauthenticated, remote attacker to perform remote code execution on
the affected device. Cisco has released free software updates that
address this vulnerability. There are no workarounds available to
mitigate this vulnerability other than disabling the Smart Install
feature."
  );
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20110928-smart-install
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f103c9d9"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20110928-smart-install."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/29");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2018 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

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
if ( version == '12.2(52)EX' ) flag++;
if ( version == '12.2(52)EX1' ) flag++;
if ( version == '12.2(52)SE' ) flag++;
if ( version == '12.2(53)EY' ) flag++;
if ( version == '12.2(53)SE' ) flag++;
if ( version == '12.2(53)SE1' ) flag++;
if ( version == '12.2(53)SE2' ) flag++;
if ( version == '12.2(55)EX' ) flag++;
if ( version == '12.2(55)EX1' ) flag++;
if ( version == '12.2(55)EX2' ) flag++;
if ( version == '12.2(55)EY' ) flag++;
if ( version == '12.2(55)EZ' ) flag++;
if ( version == '12.2(55)SE' ) flag++;
if ( version == '12.2(55)SE1' ) flag++;
if ( version == '12.2(55)SE2' ) flag++;
if ( version == '15.1(3)T' ) flag++;
if ( version == '15.1(3)T1' ) flag++;
if ( version == '15.1(4)M' ) flag++;
if ( version == '15.1(4)M0a' ) flag++;
if ( version == '15.1(4)M0b' ) flag++;
if ( version == '15.1(4)M1' ) flag++;
if ( version == '15.1(4)XB4' ) flag++;
if ( version == '15.1(4)XB5' ) flag++;

if (get_kb_item("Host/local_checks_enabled"))
{

  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_vstack_config", "show vstack config");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"Role:\s+\(Client\|Director\)", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}



if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
