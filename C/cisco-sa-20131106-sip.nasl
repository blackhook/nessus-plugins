#TRUSTED 4c39ae2bbef1e00b43ae794417b783e819bd3d93720a288ac51da25f715e79f726efc0b0a680813b5284e4e7242a21b7d50a3788bf8b408714e177de8b54283b5d2df29251fb5da87150910c7d05bfd27cbfa4e304984c7a22044f4ab252c898c72c67914f1cd600052ffda5c3ba369fa3da0190e334b82d2a7a739ca5a05b2d493945c7444fbbaaf45f7e657a48435de8a5159f05cda4479122e473e1aec0c88a6e90881e30ccdb60e0f364a213213e31ec1a2814294fd89f7b83240a639e5956e98b0431db75b7f117931c21c729c3bda8f41a2b066476d42fabef4f2685a1771cf81599bdff6701d6ebd8e3a33ebd9e57751437e9de73adda8414ab75640f3102fe11727398a73dff253655f081110458e83366760bfb1beb7f2819d990ea76b4d04187229ba6b0e225002151291e645b01bacb3cb5e1237521b1a654e86eb45c8ce74e9300bb4267aee64083ec915b7a01d6492d367e71de21daf2f7636356e292bf0e567dd3a7056ae254ec68f93dac8428c628ee189ae2b269ea9def2d3cde99fd183f3705813809b2c943def44f1d2b5c0929f33e489a0cb40d318257dfdb3290ab77dde7a13c41dd1f0d02c1804900410f14ad28414caf6a497a7857d2071d869068ac97d43f49e5099417a162fbbe87cdb208ac271af86239d819759146bfb36852d6a9d4f315f0334ffef231f209c2f85676b8443f6d2c5d0d2ba7
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20131106-sip.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(70914);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2013-5553");
  script_bugtraq_id(63553);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuc42558");
  script_xref(name:"CISCO-BUG-ID", value:"CSCug25383");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20131106-sip");

  script_name(english:"Cisco IOS Software Session Initiation Protocol Denial of Service Vulnerability (cisco-sa-20131106-sip)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"A vulnerability exists in the Session Initiation Protocol (SIP)
implementation in Cisco IOS Software that could allow an
unauthenticated, remote attacker to cause a reload of an affected
device or cause memory leaks that may result in system
instabilities. To exploit this vulnerability, affected devices must
be configured to process SIP messages. Limited Cisco IOS Software
releases are affected.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20131106-sip
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0642efe4");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20131106-sip.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/14");

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
report = "";
cbi = "CSCuc42558 and CSCug25383";
fixed_ver = "";

ver = get_kb_item_or_exit("Host/Cisco/IOS/Version");
if ( ver == '15.1(4)GC' ) flag++;
if ( ver == '15.1(4)GC1' ) flag++;
if ( ver == '15.1(4)M4' ) flag++;
if ( ver == '15.1(4)M5' ) flag++;
if ( ver == '15.1(4)M6' ) flag++;
if ( ver == '15.1(4)XB8' ) flag++;
if ( ver == '15.1(4)XB8a' ) flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_processes", "show processes");
    if (check_cisco_result(buf))
    {
      if (
           (preg(multiline:TRUE, pattern:"CCSIP_UDP_SOCKET", string:buf)) ||
           (preg(multiline:TRUE, pattern:"CCSIP_TCP_SOCKET", string:buf))
         ) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  report +=
    '\n  Cisco Bug ID        : ' + cbi +
    '\n    Installed release : ' + ver + '\n';
  security_hole(port:0, extra:report + cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
