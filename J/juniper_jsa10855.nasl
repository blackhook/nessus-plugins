#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(109216);
  script_version("1.2");
  script_cvs_date("Date: 2018/07/26 18:36:16");

  script_cve_id("CVE-2018-0022");
  script_bugtraq_id(103740);
  script_xref(name:"JSA", value:"JSA10855");

  script_name(english:"Juniper Junos VPLS Routing MPLS Packet Handling mbuf Exhaustion Remote DoS (JSA10855)");
  script_summary(english:"Checks the Junos version and build date.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Junos device
is affected by a denial of service vulnerability.");
  # https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10855&actp=METADATA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?370714f4");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in
Juniper advisory JSA10855.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');

fixes = make_array();

# 12.1X46 versions prior to 12.1X46-D76
# 12.3X48 versions prior to 12.3X48-D66, 12.3X48-D70
# 14.1 versions prior to 14.1R9
# 14.1X53 versions prior to 14.1X53-D47
# 14.2 versions prior to 14.2R8
# 15.1 versions prior to 15.1F2-S19, 15.1F6-S10, 15.1R4-S9, 15.1R5-S7, 15.1R6-S4, 15.1R7
# 15.1X49 versions prior to 15.1X49-D131, 15.1X49-D140
# 15.1X53 versions prior to 15.1X53-D58 on EX2300/EX3400
# 15.1X53 versions prior to 15.1X53-D233 on QFX5200/QFX5110
# 15.1X53 versions prior to 15.1X53-D471 on NFX
# 15.1X53 versions prior to 15.1X53-D66 on QFX10
# 16.1 versions prior to 16.1R3-S8, 16.1R4-S6, 16.1R5
# 16.2 versions prior to 16.2R1-S6, 16.2R2-S5, 16.2R3
# 17.1 versions prior to 17.1R1-S7, 17.1R2-S6, 17.1R3
# 17.2 versions prior to 17.2R1-S5, 17.2R2

fixes['12.1X46'] = '12.1X46-D76';
fixes['12.3X48'] = '12.3X48-D66'; # or D70

fixes['14.1'] = '14.1R9';
fixes['14.1X53'] = '14.1X53-D47';

fixes['14.2'] = '14.2R8';

if (ver =~ "^15\.1F2($|[^0-9])")        fixes['15.1F'] = '15.1F2-S19';
else if (ver =~ "^15\.1F6($|[^0-9])")   fixes['15.1F'] = '15.1F6-S10';
else if (ver =~ "^15\.1R4($|[^0-9])")   fixes['15.1R'] = '15.1R4-S9';
else if (ver =~ "^15\.1R5($|[^0-9])")   fixes['15.1R'] = '15.1R5-S7';
else if (ver =~ "^15\.1R6($|[^0-9])")   fixes['15.1R'] = '15.1R6-S4';
else                                    fixes['15.1R'] = '15.1R7';

fixes['15.1X49'] = '15.1X49-D131'; # or D140

if (model =~ "^EX(23|34)00")
  fixes['15.1X53'] = '15.1X53-D58';

else if (model =~ "^QFX(5200|5110)")
  fixes['15.1X53'] = '15.1X53-D233';

else if (model =~ "^NFX")
  fixes['15.1X53'] = '15.1X53-D471';

else if (model =~ "^QFX10")
  fixes['15.1X53'] = '15.1X53-D66';

if (ver =~ "^16\.1R3($|[^0-9])")        fixes['16.1R'] = '16.1R3-S8';
else if (ver =~ "^16\.1R4($|[^0-9])")   fixes['16.1R'] = '16.1R4-S6';
else                                    fixes['16.1R'] = '16.1R5';

if (ver =~ "^16\.2R1($|[^0-9])")        fixes['16.2R'] = '16.2R1-S6';
else if (ver =~ "^16\.2R1($|[^0-9])")   fixes['16.2R'] = '16.2R2-S5';
else                                    fixes['16.2R'] = '16.2R3';

# 17.1 versions prior to 17.1R1-S7, 17.1R2-S6, 17.1R3
# 17.2 versions prior to 17.2R1-S5, 17.2R2

if (ver =~ "^17\.1R1($|[^0-9])")        fixes['17.1R'] = '17.1R1-S7';
else if (ver =~ "^17\.1R4($|[^0-9])")   fixes['17.1R'] = '17.1R2-S6';
else                                    fixes['17.1R'] = '17.1R3';

if (ver =~ "^17\.2R1($|[^0-9])")        fixes['17.2R'] = '17.2R1-S5';
else                                    fixes['17.2R'] = '17.2R2';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

override = FALSE;

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
