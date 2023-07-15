#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(109215);
  script_version("1.2");
  script_cvs_date("Date: 2018/07/26 18:36:16");

  script_cve_id("CVE-2018-0021");
  script_xref(name:"JSA", value:"JSA10854");

  script_name(english:"Juniper Junos Short MacSec Keys Configuration CKN / CAK Key Extension Brute-force Mitm Spoofing (JSA10854)");
  script_summary(english:"Checks the Junos version and build date.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Junos device
is affected by man-in-the-middle spoofing vulnerability.");
  # https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10854&actp=METADATA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b9b88f7e");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in
Juniper advisory JSA10854.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");

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

fixes = make_array();

# 14.1 versions prior to 14.1R10, 14.1R9
# 14.1X53 versions prior to 14.1X53-D47
# 15.1 versions prior to 15.1R4-S9, 15.1R6-S6, 15.1R7
# 15.1X49 versions prior to 15.1X49-D100
# 15.1X53 versions prior to 15.1X53-D59
# 16.1 versions prior to 16.1R3-S8, 16.1R4-S8, 16.1R5
# 16.2 versions prior to 16.2R1-S6, 16.2R2
# 17.1 versions prior to 17.1R2

fixes['14.1'] = '14.1R9'; # or 14.1R10
fixes['14.1X53'] = '14.1X53-D47';

if (ver =~ "^15\.1R4($|[^0-9])")        fixes['15.1R'] = '15.1R4-S9';
else if (ver =~ "^15\.1R6($|[^0-9])")   fixes['15.1R'] = '15.1R6-S6';
else                                    fixes['15.1R'] = '15.1R7';

fixes['15.1X49'] = '15.1X49-D100';
fixes['15.1X53'] = '15.1X53-D59';

if (ver =~ "^16\.1R3($|[^0-9])")        fixes['16.1R'] = '16.1R3-S8';
else if (ver =~ "^16\.1R4($|[^0-9])")   fixes['16.1R'] = '16.1R4-S8';
else                                    fixes['16.1R'] = '16.1R5';

if (ver =~ "^16\.2R1($|[^0-9])")        fixes['16.2R'] = '16.2R1-S6';
else                                    fixes['16.2R'] = '16.2R2';

fixes['17.1'] = '17.1R2';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

override = FALSE;

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
