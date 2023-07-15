#TRUSTED 83d0cc696f2096297d444191120f7418a04d9b999b69cae933d019251fabd78f467a7158fc6f037495bf7c14a21e89234fff7542d629b4e9a772c9e384ff447102b0bb282a4f556fdea7c6113c5e7fc7f746c62864b16dea37a7eee67c967edc1ed1a4e44da4928006088ecd380c8d27583c7a3296ba22efeec5afb38d204f8acfcc23039b7f62f3caa3f6182dc81b4fe9724b0989d80a89c211374c5d2908dec2ed55308f4df02af55ee638812d628958768f244837c08cd5ba14c23a6ec8a46e118618b943dd4647f7a5bde3ffde1fb86acbd485b62a708ab5aa0bf22239ef2a3a822766f02dcfaa2090c0c70edc3c2eb96ace41743405a04965a3124f9794d158b6b5b7dc22c2170133ca322b4c5c7708b07d4bd0fbd524e56d1800000dbefc18d24643535ea3ceba2bfa3c974f75c0d4df439c850db48686d49de5b34dbd267d58a49a7abdec571cf305963fa3202889c99f7a442cfaeb63fdd3cba4d214cb5f4898fd8c606c084b3615b7bf1758ae0d470ee1e9977f90ddebb310084b350ee210f5846b8ae03ee6614ec9e23bc190fd220a5e749e56ce844d9911b5a8acb111feb273c8d8a4519c602279ddb8d4de8377d96e2ec22fac27c969c58b0bd9b518834b6e80fcd017aad9c5abeeb2c65ea96f3ffbe448b529a681acfe75516e3d0bce60def1f19714c17ad297d0955133e17887f1474c70e28f52e9ebd8fc86
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102700);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/08/10");

  script_cve_id("CVE-2017-2314");
  script_xref(name:"JSA", value:"JSA10779");

  script_name(english:"Juniper Junos Protocol Daemon (RPD) BGP OPEN Message Handling DoS (JSA10779)");
  script_summary(english:"Checks the Junos version and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number and configuration, the
remote Juniper Junos device is affected by a denial of service
vulnerability in the routing protocol daemon (rpd) due to improper
handling of BGP OPEN messages. An unauthenticated, remote attacker can
exploit this, via a specially crafted BGP OPEN message, to repeatedly
crash and restart the rpd daemon.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10779");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant Junos software release referenced in Juniper
security advisory JSA10779.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/23");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
# Commands ran may not be available on all models
if (report_paranoia < 2) audit(AUDIT_PARANOID);

fixes = make_array();
fixes['12.3X48'] = '12.3X48-D50';

if (ver =~ "^12\.3R12")       fixes['12.3R'] = '12.3R12-S4';
else if (ver =~ "^12\.3R3")   fixes['12.3R'] = '12.3R3-S4';
else                          fixes['12.3R'] = '12.3R13';
if (ver =~ "^13\.3R4")        fixes['13.3R'] = '13.3R4-S11';
else                          fixes['13.3R'] = '13.3R10';
if (ver =~ "^14\.1R8")        fixes['14.1R'] = '14.1R8-S3';
else                          fixes['14.1R'] = '14.1R9';
fixes['14.1X53'] = '14.1X53-D40';
fixes['14.1X55'] = '14.1X55-D35';
if (ver =~ "^14\.2R4")        fixes['14.2R'] = '14.2R4-S7';
else if (ver =~ "^14\.2R6")   fixes['14.2R'] = '14.2R6-S4';
else                          fixes['14.2R'] = '14.2R7';
if ( ver =~ "^15\.1F2")       fixes['15.1F'] = '15.1F2-S11';
else if ( ver =~ "^15\.1F4")  fixes['15.1F'] = '15.1F4-S1-J1';
else if ( ver =~ "^15\.1F5")  fixes['15.1F'] = '15.1F5-S3';
else                          fixes['15.1F'] = '15.1F6';
fixes['15.1X49'] = '15.1X49-D100';
fixes['15.1X53'] = '15.1X53-D33'; # or 15.1X53-D50
fixes['15.1'] = '15.1R4';
fixes['16.1'] = '16.1R1';
fixes['16.2'] = '16.2R1';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

override = TRUE;
buf = junos_command_kb_item(cmd:"show bgp neighbor");
if (buf)
{
  if (preg(string:buf, pattern:"BGP.* instance is not running", icase:TRUE, multiline:TRUE))
    audit(AUDIT_HOST_NOT, "affected because BGP is not enabled"); 
  else
    override = FALSE;
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
