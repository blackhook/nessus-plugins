#TRUSTED 4560a47f731c40b88764eb4e9d2b05fb6ebb9c3dfa32867e928ed3eb5484ebe03f4357797a56409b626e87fd233909374d79f9739db9a47153f0fec34e68536a9b3481f6e025ead78cdf1376d3dc9400dcba0df00ac9c137ccb23697f06b7dacd1e52dd194cca94df80c057f52ef20b27e2dea1fd8cb009bb1c247f521d42548387861ced41b159048a3985291264eb96ba42452b8a9493ad4d6263c937104493514a64e7b7b11b06032caeb11d4c576478ca41b8838e81ce1f7efefa9f1689e28470b071fb7bc0fc9ebbeb96929d21ee3d66ac9fe7444eb867af69013edc3d8f0baaf6ee08b79b30bd8f44cb34a08a31bd5ad5f30a1c18d1dddfa0dfed5af68c977093d43c058a375975c6a28d59834346df0bcd3df7ca0f9449ac1454f4215fdd9bff068bf451b666cba0e5d4ab3d533eb9125caf8bc14cea5800c37f14ed3d38a8861452419ee6edb482f92b9ee5eb3a8191a2777c00dba70c73c36dbbc7bba0054a1bf04a164b39848eaf3a6a6cb4f4912cff1acec3d36c03832b756a49e29ccf49c5d5ff816c26849e5f9b45813054ffab1d581e2c74a239837345887bd2b8ae6068a5f93199b9c10e70d657af88feff7a725ef0eee2bd293a9e1c8a8e5b54b47cdba972758c6a030ea7fe921c4ab9d608d280851f036ddb8f438c6e6d3629bee8e6d91dce2fd834cd09b9654a4c8837d73b0479d3a5d550ade55037498
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20120328-smartinstall.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(58572);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2012-0385");
  script_bugtraq_id(52756);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtt16051");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20120328-smartinstall");

  script_name(english:"Cisco IOS Software Smart Install Denial of Service Vulnerability (cisco-sa-20120328-smartinstall)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Cisco IOS Software contains a vulnerability in the Smart Install
feature that could allow an unauthenticated, remote attacker to cause
a reload of an affected device if the Smart Install feature is
enabled. The vulnerability is triggered when an affected device
processes a malformed Smart Install message on TCP port 4786. Cisco
has released free software updates that address this vulnerability. A
workaround may be available in some versions of Cisco IOS Software if
the Smart Install feature is not needed."
  );
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20120328-smartinstall
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c603908e"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20120328-smartinstall."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/02");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2018 Tenable Network Security, Inc.");
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
if ( version == '12.2(55)EX3' ) flag++;
if ( version == '12.2(55)EY' ) flag++;
if ( version == '12.2(55)EZ' ) flag++;
if ( version == '12.2(55)SE' ) flag++;
if ( version == '12.2(55)SE1' ) flag++;
if ( version == '12.2(55)SE2' ) flag++;
if ( version == '12.2(55)SE3' ) flag++;
if ( version == '12.2(55)SE4' ) flag++;
if ( version == '12.2(58)EY' ) flag++;
if ( version == '12.2(58)EY1' ) flag++;
if ( version == '12.2(58)EY2' ) flag++;
if ( version == '12.2(58)SE' ) flag++;
if ( version == '12.2(58)SE1' ) flag++;
if ( version == '12.2(58)SE2' ) flag++;
if ( version == '15.0(1)SE' ) flag++;
if ( version == '15.1(3)T' ) flag++;
if ( version == '15.1(3)T1' ) flag++;
if ( version == '15.1(3)T2' ) flag++;
if ( version == '15.1(4)M' ) flag++;
if ( version == '15.1(4)M0a' ) flag++;
if ( version == '15.1(4)M0b' ) flag++;
if ( version == '15.1(4)M1' ) flag++;
if ( version == '15.1(4)M2' ) flag++;
if ( version == '15.1(4)M3' ) flag++;
if ( version == '15.1(4)M3a' ) flag++;
if ( version == '15.1(4)XB4' ) flag++;
if ( version == '15.1(4)XB5' ) flag++;
if ( version == '15.1(4)XB6' ) flag++;
if ( version == '15.2(1)GC' ) flag++;
if ( version == '15.2(1)GC1' ) flag++;
if ( version == '15.2(1)T' ) flag++;
if ( version == '15.2(1)T1' ) flag++;
if ( version == '15.2(2)T' ) flag++;

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
