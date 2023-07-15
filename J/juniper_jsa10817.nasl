#TRUSTED 086e35fd3fde92cac731c7311a20c1c6dc0175e214a92a19682d4469478923f154669abbda74491ca0353d79c1cff65a9c8b2957631dd4ae3bbb20b556f3b0dc83edaab3fd414120ab50d762c8ee549bd89485058430426769992c9dd97e11bea7dbd61f0a938e644508d79cf05fb38af3f9ead36e06b63ec3eec2c327657c5431ac6938f2364c25ba49f8915a681e2cf4d67cba6d0ef08e8d596ade5505279c3c22f56d539c2a1e309e52bbccbf451e54d13e59950ba4fbf2b390c6129032f9bccbd1fc9a9fe8d951cca9bb7c2d1aa03e2e5ac0891f626e300e41bfa030f3658e2ceffa170b8d138ce10e5c6f11fda0ee2db604002e6178e3cb65203fc4063ee7846c6569b04279bdc8798df321c591f8bf6370796262ef1a67a90462b7f9fa5b2231417614e8dfe6f66065844d7d4c5f7f9b99d36fceea9702e3fc1b28203109ef0f03ea58bf18ad080fd91baff49283bee362f4aded35845d9e509b8b106b1aad2fc3e7b2208a7804085cb6d85e290132cde9968582fd20562f56c9552cc82f0e8979922dbcf0cae39c16cbe87ea7ff49ccc74e64770be4b722cbcde9865f9070374abecf940da4c9793414b356b3a1f12c3e7bb5e8325738131a23a6ded24ee7591b859387d9a5137d86011dda712d44a1dd1423103dd68007b3065d8f1b27d0a4ca49558826559f4bea21293f861b19eacd3ad1186e58849ebb6fd58b41
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104037);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/08/10");

  script_cve_id("CVE-2017-10614","CVE-2017-10621");
  script_xref(name:"JSA", value:"JSA10816");

  script_name(english:"Juniper Junos DoS Telnet Vulnerability (JSA10817)");
  script_summary(english:"Checks the Junos version and build date.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Junos device
is affected by two vulnerabilities in the telnetd service that 
may allow a remote unauthenticated attacker to cause a denial of service 
through memory and/or CPU consumption.");
  # https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10817&actp=METADATA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d927783");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workarounds referenced in
Juniper advisory JSA10817.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');


# Affected:
# 12.1X46 prior to 12.1X46-D71
# 12.3X48 prior to 12.3X48-D50
# 14.1 prior to 14.1R8-S5 or 14.1R9
# 14.1X53 prior to 14.1X53-D46
# 14.2 prior to 14.2R4-S9 or 14.2R7-S8 or 14.2R8
# 15.1 prior to 15.1F5-S6 or 15.1F6
# 15.1X49 prior to 15.1X49-D90
# 15.1X53 prior to 15.1X53-D47
# 16.1 prior to 16.1R4-S1 or 16.1R5
# 16.2 prior to 16.2R1-S3 or 16.2R2
# 17.1 prior to 17.1R1
fixes = make_array();
fixes['12.1X46']     = '12.1X46-D71';
fixes['12.3X48']     = '12.3X48-D50';
fixes['14.1']        = '14.1R8-S5';
fixes['14.1X53']     = '14.1X53-D46';
fixes['14.2']        = '14.2R4-S9';
fixes['15.1X49']     = '15.1X49-D60';
fixes['15.1X53']     = '15.1X53-D47';
fixes['15.1R']       = '15.1R5-S2';
fixes['15.1X49']     = '15.1X49-D90';
fixes['15.1X53']     = '15.1X53-D47';
fixes['16.1']        = '16.1R4-S1';
fixes['16.2']        = '16.2R1-S3';
fixes['17.1']        = '17.1R1';

if (ver =~ "^15\.1F[0-2]")  fixes['15.1F'] = '15.1F2-S16';
else if (ver =~ "^15\.1F5") fixes['15.1F'] = '15.1F5-S7';
else if (ver =~ "^15\.1F6") fixes['15.1F'] = '15.1F6-S6';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set system services telnet";
  if (!junos_check_config(buf:buf, pattern:pattern)){
    audit(AUDIT_HOST_NOT, 'affected because telnet is not enabled');
  }
  override = FALSE;
}
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
