#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106385);
  script_version("1.4");
  script_cvs_date("Date: 2018/07/12 19:01:16");

  script_cve_id("CVE-2018-0001");
  script_xref(name:"JSA", value:"JSA10828");

  script_name(english:"Juniper Junos J-Web Interface PHP URL Handling Use-after-free RCE (JSA10828)");
  script_summary(english:"Checks the Junos version and build date.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Junos device
is affected by a remote code execution vulnerability.");
  # https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10828&actp=METADATA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c0ebe9da");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in
Juniper advisory JSA10828.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
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
# 12.1X46 prior to 12.1X46-D67
# 12.3 prior to 12.3R12-S5
# 12.3X48 prior to 12.3X48-D35
# 14.1 prior to 14.1R8-S5, 14.1R9
# 14.1X53 prior to 14.1X53-D44, 14.1X53-D50
# 14.2 prior to 14.2R7-S7, 14.2R8
# 15.1 prior to 15.1R3
# 15.1X49 prior to 15.1X49-D30
# 15.1X53 prior to 15.1X53-D70
fixes = make_array();
fixes['12.1X46']  = '12.1X46-D67';
fixes['12.3']     = '12.3R12-S5';
fixes['12.3X48']  = '12.3X48-D35';
if (ver =~ "^14\.1R8")
  fixes['14.1']   = '14.1R8-S5';
else
  fixes['14.1']     = '14.1R9';
fixes['14.1X53']  = '14.1X53-D44'; # or 14.1X53-D50
if (ver =~ "^14\.2R7")
  fixes['14.2R7']   = '14.2R7-S7';
else
  fixes['14.2']     = '14.2R8';
fixes['15.1']     = '15.1R3';
fixes['15.1X49']  = '15.1X49-D30';
fixes['15.1X53']  = '15.1X53-D70';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

override = FALSE;

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
