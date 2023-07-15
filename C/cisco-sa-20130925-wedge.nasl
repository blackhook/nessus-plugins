#TRUSTED 64ea60e7f4894a7be288dcd471e9fd4387b83de2588c3b2476cf79867c4f03f1028516757be980fdb24dd8c0dc0e351373178d6b82f292dfcc0524159e7f529f94df5cb5d29de1da8e5253009b2ecab5320d7db5c4e291b1da72b9d24345386e3d971213fc0a7126c018b30288e54943ebbed330f0335eb8a491d53cad78bc2e9e6705697e559ccaa44295e56e5fb524e4e0667052b07fa050b841bc7e382f80e93e6902740aa2113072f3846432188c178d5a26134d3a5bee68cffb1b57ecb6080a51c0cb854c54b2e8368442dac27e0018373dd98899671215449ef8c7415cda989a2876e14fe56f43c4a0dcd8969c74496d99017df9230ed3cb40f1b9fcfc79493234e0c6b2fcd019d89d99fd6a53e126cb5a3fc8f526a628235309178184304ea7431f5d4253fa6a686fb4969fa1ee46aafe11c7116eb0adc206c95b498d876feb951c3c8c54c6151b6e2b58a238734d0a26e080c63390a2a1e4f5cad703c4fb12ddf873effa6cb3cd8e748a96054f45f28816bebe0fd482e8e223ccbba476b04cd724d7c52b5bf7c7ba693992485d2cd02d62202e762ec921b02051e6646a511d906eb7402cec22d5c650d199248b176371706f1945272d3649a2c91646ebdd6ffcf4f6c0869d093be2238f114f0df0112128f814cada6e91cf4f0bf5cd7ed9ab138e548f575c17c3068a375eb3c06eae700883b2dc4d35e24a0f478d1c
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20130925-wedge.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(70323);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2013-5477");
  script_bugtraq_id(62645);
  script_xref(name:"CISCO-BUG-ID", value:"CSCub67465");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130925-wedge");

  script_name(english:"Cisco IOS Software Queue Wedge Denial of Service Vulnerability (cisco-sa-20130925-wedge)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"A vulnerability in the T1/E1 driver queue implementation of Cisco IOS
Software could allow an unauthenticated, remote attacker to cause an
interface wedge condition, which could lead to loss of connectivity,
loss of routing protocol adjacency, and could result in a denial of
service (DoS) scenario. The vulnerability is due to incorrect
implementation of the T1/E1 driver queue. An attacker could exploit
this vulnerability by sending bursty traffic through the affected
interface driver. Repeated exploitation could cause a DoS condition.
Workarounds to mitigate this vulnerability are available. Cisco has
released free software updates that address this vulnerability."
  );
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130925-wedge
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a2ee7b4e"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20130925-wedge."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/07");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2018 Tenable Network Security, Inc.");
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
if ( version == '15.0(1)M' ) flag++;
if ( version == '15.0(1)M1' ) flag++;
if ( version == '15.0(1)M10' ) flag++;
if ( version == '15.0(1)M2' ) flag++;
if ( version == '15.0(1)M3' ) flag++;
if ( version == '15.0(1)M4' ) flag++;
if ( version == '15.0(1)M5' ) flag++;
if ( version == '15.0(1)M6' ) flag++;
if ( version == '15.0(1)M6a' ) flag++;
if ( version == '15.0(1)M7' ) flag++;
if ( version == '15.0(1)M8' ) flag++;
if ( version == '15.0(1)M9' ) flag++;
if ( version == '15.0(1)XA' ) flag++;
if ( version == '15.0(1)XA1' ) flag++;
if ( version == '15.0(1)XA2' ) flag++;
if ( version == '15.0(1)XA3' ) flag++;
if ( version == '15.0(1)XA4' ) flag++;
if ( version == '15.0(1)XA5' ) flag++;
if ( version == '15.1(1)T' ) flag++;
if ( version == '15.1(1)T1' ) flag++;
if ( version == '15.1(1)T2' ) flag++;
if ( version == '15.1(1)T3' ) flag++;
if ( version == '15.1(1)T4' ) flag++;
if ( version == '15.1(1)T5' ) flag++;
if ( version == '15.1(1)XB' ) flag++;
if ( version == '15.1(1)XB1' ) flag++;
if ( version == '15.1(1)XB2' ) flag++;
if ( version == '15.1(1)XB3' ) flag++;
if ( version == '15.1(2)GC' ) flag++;
if ( version == '15.1(2)GC1' ) flag++;
if ( version == '15.1(2)GC2' ) flag++;
if ( version == '15.1(2)T' ) flag++;
if ( version == '15.1(2)T0a' ) flag++;
if ( version == '15.1(2)T1' ) flag++;
if ( version == '15.1(2)T2' ) flag++;
if ( version == '15.1(2)T2a' ) flag++;
if ( version == '15.1(2)T3' ) flag++;
if ( version == '15.1(2)T4' ) flag++;
if ( version == '15.1(2)T5' ) flag++;
if ( version == '15.1(3)T' ) flag++;
if ( version == '15.1(3)T1' ) flag++;
if ( version == '15.1(3)T2' ) flag++;
if ( version == '15.1(3)T3' ) flag++;
if ( version == '15.1(3)T4' ) flag++;
if ( version == '15.1(4)GC' ) flag++;
if ( version == '15.1(4)GC1' ) flag++;
if ( version == '15.1(4)M' ) flag++;
if ( version == '15.1(4)M0a' ) flag++;
if ( version == '15.1(4)M0b' ) flag++;
if ( version == '15.1(4)M1' ) flag++;
if ( version == '15.1(4)M2' ) flag++;
if ( version == '15.1(4)M3' ) flag++;
if ( version == '15.1(4)M3a' ) flag++;
if ( version == '15.1(4)M4' ) flag++;
if ( version == '15.1(4)M5' ) flag++;
if ( version == '15.1(4)M6' ) flag++;
if ( version == '15.1(4)XB4' ) flag++;
if ( version == '15.1(4)XB5' ) flag++;
if ( version == '15.1(4)XB5a' ) flag++;
if ( version == '15.1(4)XB6' ) flag++;
if ( version == '15.1(4)XB7' ) flag++;
if ( version == '15.1(4)XB8a' ) flag++;
if ( version == '15.2(1)GC' ) flag++;
if ( version == '15.2(1)GC1' ) flag++;
if ( version == '15.2(1)GC2' ) flag++;
if ( version == '15.2(1)T' ) flag++;
if ( version == '15.2(1)T1' ) flag++;
if ( version == '15.2(1)T2' ) flag++;
if ( version == '15.2(1)T3' ) flag++;
if ( version == '15.2(1)T3a' ) flag++;
if ( version == '15.2(1)T4' ) flag++;
if ( version == '15.2(100)T' ) flag++;
if ( version == '15.2(2)GC' ) flag++;
if ( version == '15.2(2)JA' ) flag++;
if ( version == '15.2(2)JA1' ) flag++;
if ( version == '15.2(2)JAX' ) flag++;
if ( version == '15.2(2)JB' ) flag++;
if ( version == '15.2(2)JB1' ) flag++;
if ( version == '15.2(2)T' ) flag++;
if ( version == '15.2(2)T1' ) flag++;
if ( version == '15.2(2)T2' ) flag++;
if ( version == '15.2(2)T3' ) flag++;
if ( version == '15.2(3)GC' ) flag++;
if ( version == '15.2(3)GC1' ) flag++;
if ( version == '15.2(3)GCA' ) flag++;
if ( version == '15.2(3)T' ) flag++;
if ( version == '15.2(3)T1' ) flag++;
if ( version == '15.2(3)T2' ) flag++;
if ( version == '15.2(3)T3' ) flag++;
if ( version == '15.2(3)XA' ) flag++;
if ( version == '15.2(4)JA' ) flag++;
if ( version == '15.2(4)M' ) flag++;
if ( version == '15.2(4)M1' ) flag++;
if ( version == '15.2(4)M2' ) flag++;
if ( version == '15.2(4)XB10' ) flag++;
if ( version == '15.3(1)T' ) flag++;
if ( version == '15.3(1)T1' ) flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_interfaces", "show interfaces");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"address is [1-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,3}\r\n( +.*\r\n){1,3} +[Ee]ncapsulation HDLC", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }

    if (flag)
    {
      flag = 0;
      buf = cisco_command_kb_item("Host/Cisco/Config/show_controllers_e1", "show controllers e1");
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"[Ll]ine", multiline:TRUE, string:buf)) { flag = 1; }
        if (preg(pattern:"[Ii]nternal", multiline:TRUE, string:buf)) { flag = 1; }
      } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }

      buf = cisco_command_kb_item("Host/Cisco/Config/show_controllers_t1", "show controllers t1");
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"[Ll]ine", multiline:TRUE, string:buf)) { flag = 1; }
        if (preg(pattern:"[Ii]nternal", multiline:TRUE, string:buf)) { flag = 1; }
      } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
    }
    else { flag = 0; }
  }
}



if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
