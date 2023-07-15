#TRUSTED afc2cce6904c72c241fbfed3496dc11d31643d83c8835dcb3e891ae35f1457608d1f75ebd25a82315f0d45c9ce390d9ecfe49724db114405c07fe485f4241b06259046ec80d636956382ad8855d6315efab362f2dd00e6f5ec222e357745384f02d78d77d3d83fb8cb97719291f68aa08620c93f2cb39602f53697d5c1cc90558213c0d88fba41e76c2daf67a352846dbf2c4f0d2170d9d8a3a712f6815d469721e2728078c8a3c98141c3e046fb049bf0052942e1ea0fe0cc6d9ad98b5c9f534570e98dcc9a3958cfb580ea37cc16d4c16c9edbfde4c74fe7aaf7d65368c5ee314a49530819392b245b297251d16b4498a43424ed86a986b12b4180acff08f919823e4cc3726de2ddcd52107574cdb92c9edc055a31f60c5499094698b7683c2a23beb825ddcd90bbf2e49cef94bbc48295ee4e322231ed22449ffb658c1f8e00d5f8b7f762c3fcee4a589aefe44ea22ecbd883ee4207e6507f0647a7516b55540f72151114d157e95e5f145bc3d49557d16b8f5a606ae5306bb44ea6c7aa6761fff08ff0cd9f46b3c9307a94b37e9acf0487bc38ebf3e3c6b33007be56a108eaa22e5656037b386de3785cdf2c96cf1c0955556ee8cd41583b85daf355cba956f2c06fcfc54be8ecc3462b67a58b4a2a28a42584b5dd0758a5ca874e53449e35ef85fb9f36e09ef84e1a090829aa37cb627be0ee9cc5175edb5c85d265c7c5
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78425);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/07/12");

  script_cve_id("CVE-2014-6379");
  script_bugtraq_id(70365);
  script_xref(name:"JSA", value:"JSA10654");

  script_name(english:"Juniper Junos RADIUS Security Bypass (JSA10654)");
  script_summary(english:"Checks the Junos version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by a security bypass vulnerability. This
issue is caused by RADIUS accounting servers being used for
authentication requests. An authenticated attacker can exploit this to
bypass authentication.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10654");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10654.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

fixes = make_array();
fixes['11.4']    = '11.4R12';
fixes['12.1']    = '12.1R10';
fixes['12.1X44'] = '12.1X44-D35';
fixes['12.1X45'] = '12.1X45-D25';
fixes['12.1X46'] = '12.1X46-D20';
fixes['12.1X47'] = '12.1X47-D10';
fixes['12.2']    = '12.2R8';
fixes['12.2X50'] = '12.2X50-D70';
fixes['12.3']    = '12.3R6';
fixes['13.1']    = '13.1R4-S3';
fixes['13.1X49'] = '13.1X49-D55';
fixes['13.1X50'] = '13.1X50-D30';
fixes['13.2']    = '13.2R4';
fixes['13.2X50'] = '13.2X50-D20';
fixes['13.2X51'] = '13.2X51-D26';
fixes['13.2X52'] = '13.2X52-D15';
fixes['13.3']    = '13.3R2';
fixes['14.1']    = '14.1R1';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

if (fix == '13.2X51-D26')
  fix = '13.2X51-D26 or 13.2X51-D30';

# Check that a RADIUS server is configured
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set system radius-server ";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'affected because RADIUS is not configured');
  override = FALSE;
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
