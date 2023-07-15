#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(132046);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/28");

  script_cve_id("CVE-2019-0061");
  script_xref(name:"JSA", value:"JSA10960");

  script_name(english:"Juniper JSA10960");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is prior to 15.1X49-D171, 15.1X53-D496, 16.1R7-S4, 16.2R2-S9,
17.1R3, 17.2R1-S8, 17.3R3-S4, 17.4R1-S6, 18.1R2-S4, 18.2R1-S5, 18.3R1-S3, or 18.4R1-S2. It is, therefore, affected by a
vulnerability as referenced in the JSA10960 advisory. Note that Nessus has not tested for this issue but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA10960");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA10960");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0061");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/13");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include("audit.inc");
include("junos.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');

if (model !~ '^PTX10003' && model !~ '^QFX5200' && model !~ 'QFX5220')
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);

fixes = make_array();

fixes["16.1"] = "16.1R7-S4";
fixes["16.2"] = "16.2R2-S9";
fixes["17.1"] = "17.1R3";
fixes["17.3"] = "17.3R3-S4";

if (report_paranoia >= 2)
{
  fixes["15.1X49"] = "15.1X49-D171"; # 15.1X49-D171, 15.1X49-D180;
  fixes["15.1X53"] = "15.1X53-D69"; # 15.1X53-D496, 15.1X53-D69;
}

# 17.2 versions prior to 17.2R1-S7, 17.2R2-S6, 17.2R3;
if (ver =~ "^17\.2R1($|[^0-9])") fixes['17.2R'] = '17.2R1-S8';
else if (ver =~ "^17\.2R2($|[^0-9])") fixes['17.2R'] = '17.2R2-S7';
else if (ver =~ "^17\.2R3($|[^0-9])") fixes['17.2R'] = '17.2R3-S1';

# 17.4 versions prior to 17.4R1-S6, 17.4R1-S7, 17.4R2-S3, 17.4R3;
if (ver =~ "^17\.4R1($|[^0-9])") fixes['17.4R'] = '17.4R1-S6';
else if (ver =~ "^17\.4R2($|[^0-9])") fixes['17.4R'] = '17.4R2-S3';
else if (ver =~ "^17\.4R3($|[^0-9])") fixes['17.4R'] = '17.4R3';

# 18.1 versions prior to 18.1R2-S4, 18.1R3-S4;
if (ver =~ "^18\.1R2($|[^0-9])") fixes['18.1R'] = '18.1R2-S4';
else if (ver =~ "^18\.1R3($|[^0-9])") fixes['18.1R'] = '18.1R3-S4';

# 18.2 versions prior to 18.2R1-S5, 18.2R2-S2, 18.2R3;
if (ver =~ "^18\.2R1($|[^0-9])") fixes['18.2R'] = '18.2R1-S5';
else if (ver =~ "^18\.2R2($|[^0-9])") fixes['18.2R'] = '18.2R2-S2';
else if (ver =~ "^18\.2R3($|[^0-9])") fixes['18.2R'] = '18.2R3';

# 18.3 versions prior to 18.3R1-S3, 18.3R2;
if (ver =~ "^18\.3R1($|[^0-9])") fixes['18.3R'] = '18.3R1-S3';
else if (ver =~ "^18\.3R2($|[^0-9])") fixes['18.3R'] = '18.3R2';

# 18.4 versions prior to 18.4R1-S2, 18.4R2;
if (ver =~ "^18\.4R1($|[^0-9])") fixes['18.4R'] = '18.4R1-S2';
else if (ver =~ "^18\.4R2($|[^0-9])") fixes['18.4R'] = '18.4R2';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);
report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
