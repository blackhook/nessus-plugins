#TRUSTED 16333ab24103b9f66cb5403e4cde3a7cb6c2f00defdfb10ed3c4f6a02bb5e9e5aa326a53f0de347a20a9e4597429767ba3a7112523f754abdc36883076236df067320dd244239bab8ec40fce6842858b016a3d4a2c93b8aec0f247373b1bf23890ada97bfd1c48021b3f85ac8fa3a6f4b7e83cae91a335de5abea4786a833d8b8c4fd77f33580aea387fa248dd1609b41c0690897324238872be65635ccb44ae5f07c51606f2bb540dad7b6c48a002de1b15360e53a6c67494a4fc8ac0eedd07159da432837e581b2eaebeaf3719c0aef3237db57427765a923564d1aa59c7c4f7493c234e92cb898770754f6ee9c7f0f08c244bc3ea01e1e7da2a5c89603220efeec1bf5b358dce63b19ec868f7f982bde464c437525ec79c737c8e0f26f4be754f8ff4e6fad7b9c11ee8e5a638aa33cc9f1ffb6676100f7ff6cf36623a45adc2f4bbe472977890838796a3b7cfc8185aafad0381025cd46e6a7b69160dfa9acac1be5f4abfa79c4c82e5c7533ebe2c9ffa522565d7fb70f3445bd33509b49fab895c867a3770fb37ca5c27298030729ce00b808fd7a3131b4cc4c197f01d299cd61c95b8bc2dc69d26688862dcf77abe1a5d386dca6550012175affaf9bd63999527501481d964b4da49d5a8bbdc8fdc2be4adbb488b041b66815dec73ed57cde1b6f92cafdd6bc92aff07d15cd38077826d0d2aed9540d2abb7558d815ee3
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71998);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/07/12");

  script_cve_id("CVE-2014-0616");
  script_bugtraq_id(64766);
  script_xref(name:"JSA", value:"JSA10609");

  script_name(english:"Juniper Junos Oversized BGP UPDATE Remote DoS (JSA10609)");
  script_summary(english:"Checks the Junos version, build date, and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by a denial of service vulnerability. This
issue exists in the routing protocol daemon (rpd) when handling
oversized BGP UPDATE messages.

Note that this issue only affects devices with BGP enabled.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10609");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10609.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/16");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/JUNOS/BuildDate");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
build_date = get_kb_item_or_exit('Host/Juniper/JUNOS/BuildDate');

if (compare_build_dates(build_date, '2013-12-20') >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver + ' (build date ' + build_date + ')');
if (ver == '12.1R8-S3' || ver == '12.3R4-S2' || ver == '13.1R3-S1' || ver == '13.2R2-S2')
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);

fixes = make_array();
fixes['10.4'] = '10.4R16';
fixes['11.4'] = '11.4R10';
fixes['12.1'] = '12.1R8';
fixes['12.1X44'] = '12.1X44-D30';
fixes['12.1X45'] = '12.1X45-D20';
fixes['12.1X46'] = '12.1X46-D10';
fixes['12.2'] = '12.2R7';
fixes['12.3'] = '12.3R5';
fixes['13.1'] = '13.1R3';
fixes['13.2'] = '13.2R2';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# BGP must be enabled
override = TRUE;
buf = junos_command_kb_item(cmd:"show bgp summary");
if (buf)
{
  if ("BGP is not running" >< buf)
    audit(AUDIT_HOST_NOT, 'affected because BGP is not enabled');
  override = FALSE;
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
