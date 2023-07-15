#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106392);
  script_version("1.4");
  script_cvs_date("Date: 2018/07/12 19:01:16");

  script_cve_id("CVE-2018-0008");
  script_xref(name:"JSA", value:"JSA10835");

  script_name(english:"Juniper Junos Commit Script Handling Local Console Port Access Weakness Vulnerability (JSA10835)");
  script_summary(english:"Checks the Junos version and build date.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Junos device
is affected by a authentication bypass vulnerability.");
  # https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10835&actp=METADATA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7c3fa562");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in
Juniper advisory JSA10835.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/26");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');

# Affected:
# 12.1X46 versions prior to 12.1X46-D71 on SRX
# 12.3X48 versions prior to 12.3X48-D55 on SRX
# 14.1 versions prior to 14.1R9
# 14.1X53 versions prior to 14.1X53-D40 on QFX, EX
# 14.2 versions prior to 14.2R7-S9, 14.2R8
# 15.1 versions prior to 15.1F5-S7, 15.1F6-S8, 15.1R5-S6, 15.1R6
# 15.1X49 versions prior to 15.1X49-D110 on SRX
# 15.1X53 versions prior to 15.1X53-D232 on QFX5200/5110
# 15.1X53 versions prior to 15.1X53-D49, 15.1X53-D470 on NFX
# 15.1X53 versions prior to 15.1X53-D65 on QFX10K
# 16.1 versions prior to 16.1R2
fixes = make_array();

if (model =~ "^SRX")
{
  fixes['12.1X46'] = '12.1X46-D71';
  fixes['12.3X48'] = '12.3X48-D55';
  fixes['15.1X49'] = '15.1X49-D110';
}
else if (model =~ "^EX")
{
  fixes['14.1X53'] = '14.1X53-D40';
}
else if (model =~ "^NFX")
{
  fixes['15.1X53'] = '15.1X53-D49'; # or 15.1X53-D470
}
else if (model =~ "^QFX5(200|110)")
{
  fixes['14.1X53'] = '14.1X53-D40';
  fixes['15.1X53'] = '15.1X53-D232';
}
else if (model =~ "^QFX10K")
{
  fixes['14.1X53'] = '14.1X53-D40';
  fixes['15.1X53'] = '15.1X53-D65';
}
else if (model =~ "^QFX")
{
  fixes['14.1X53'] = '14.1X53-D40';

}

fixes['14.1'] = '14.1R9';
fixes['14.2'] = '14.2R8';
if (ver =~ "^15\.1F5")
  fixes['15.1'] = '15.1F5-S7';
else if (ver =~ "^15\.1F6")
  fixes['15.1'] = '15.1F6-S8';
else if (ver =~ "^15\.1R5")
  fixes['15.1'] = '15.1R5-S6';
else
  fixes['15.1'] = '15.1R6';
fixes['16.1'] = '16.1R2';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

override = FALSE;

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
