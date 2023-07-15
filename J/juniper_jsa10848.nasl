#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(109214);
  script_version("1.2");
  script_cvs_date("Date: 2018/07/26 18:36:16");

  script_cve_id("CVE-2018-0020");
  script_xref(name:"JSA", value:"JSA10848");

  script_name(english:"Juniper Junos Routing Process Daemon (RPD) BGP UPDATE Packet Handling Unspecified Remote DoS (JSA10848)");
  script_summary(english:"Checks the Junos version and build date.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Junos device
is affected by a remote denial of service vulnerability.");
  # https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10848&actp=METADATA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e726484f");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in
Juniper advisory JSA10848.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:H/A:N");

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

# 15.1X49 versions prior to 15.1X49-D130 on SRX
if (model =~ '^SRX')
  fixes['15.1X49'] = '15.1X49-D130';

# 15.1X53 versions prior to 15.1X53-D66 on QFX10K
else if (model =~ '^QFX10K')
  fixes['15.1X53'] = '15.1X53-D66';

# 15.1X53 versions prior to 15.1X53-D58 on EX2300/EX3400
else if (model =~ '^EX(23|34)00')
  fixes['15.1X53'] = '15.1X53-D58';

# 15.1X53 versions prior to 15.1X53-D233 on QFX5200/QFX5110
else if (model =~ '^QFX(5200|5110)')
  fixes['15.1X53'] = '15.1X53-D233';

# 15.1X53 versions prior to 15.1X53-D471 on NFX
else if (model =~ '^NFX')
  fixes['15.1X53'] = '15.1X53-D471';

# 14.1X53 versions prior to 14.1X53-D47
# 15.1 versions prior to 15.1F6-S10, 15.1R4-S9, 15.1R6-S6, 15.1R7
# 16.1 versions prior to 16.1R3-S8, 16.1R4-S9, 16.1R5-S3, 16.1R6-S3, 16.1R7
# 16.1X65 versions prior to 16.1X65-D47
# 16.2 versions prior to 16.2R1-S6, 16.2R2-S5, 16.2R3
# 17.1 versions prior to 17.1R2-S3, 17.1R3
# 17.2 versions prior to 17.2R1-S3, 17.2R2-S1, 17.2R3
# 17.2X75 versions prior to 17.2X75-D70

fixes['14.1X53'] = '14.1X53-D47';

if (ver =~ "^15\.1F6($|[^0-9])")        fixes['15.1F'] = '15.1F6-S10';
else if (ver =~ "^15\.1R4($|[^0-9])")   fixes['15.1R'] = '15.1R4-S9';
else if (ver =~ "^15\.1R6($|[^0-9])")   fixes['15.1R'] = '15.1R6-S6';
else                                    fixes['15.1R'] = '15.1R7';

if (ver =~ "^16\.1R3($|[^0-9])")        fixes['16.1R'] = '16.1R3-S8';
else if (ver =~ "^16\.1R4($|[^0-9])")   fixes['16.1R'] = '16.1R4-S9';
else if (ver =~ "^16\.1R5($|[^0-9])")   fixes['16.1R'] = '16.1R5-S3';
else if (ver =~ "^16\.1R6($|[^0-9])")   fixes['16.1R'] = '16.1R6-S3';
else                                    fixes['16.1R'] = '16.1R7';

fixes['16.1X65'] = '16.1X65-D47';
fixes['16.1X70'] = '16.1X70-D10';

if (ver =~ "^16\.2R1($|[^0-9])")        fixes['16.2R'] = '16.2R1-S6';
else if (ver =~ "^16\.2R2($|[^0-9])")   fixes['16.2R'] = '16.2R2-S5';
else                                    fixes['16.2R'] = '16.2R3';

if (ver =~ "^17\.1R2($|[^0-9])")        fixes['17.1R'] = '17.1R2-S3';
else                                    fixes['17.1R'] = '17.1R3';

if (ver =~ "^17\.2R1($|[^0-9])")        fixes['17.2R'] = '17.2R1-S3';
else if (ver =~ "^17\.2R2($|[^0-9])")   fixes['17.2R'] = '17.2R2-S1';
else                                    fixes['17.2R'] = '17.2R3';

fixes['17.2X75'] = '17.2X75-D70';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

override = FALSE;

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
