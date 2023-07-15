#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102705);
  script_version("1.3");
  script_cvs_date("Date: 2018/07/12 19:01:16");

  script_cve_id("CVE-2017-2344");
  script_bugtraq_id(99556);
  script_xref(name:"JSA", value:"JSA10792");

  script_name(english:"Juniper Junos Sockets Library Buffer Overflow Privilege Escalation (JSA10792)");
  script_summary(english:"Checks the Junos version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by a privilege escalation vulnerability in
the sockets library due to a buffer overflow condition. A local
attacker can exploit this to cause a denial of service (kernel panic)
or the execution of arbitrary code with elevated privileges.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10792");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant Junos software release referenced in Juniper
security advisory JSA10792.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/23");

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
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
fixes = make_array();

fixes['12.1X46'] = '12.1X46-D67';
fixes['12.3X48'] = '12.3X48-D51'; # or 12.3X48-D55

if ( ver =~ "^13\.3R10")      fixes['13.3R'] = '13.3R10-S2';
if (ver=~"^14\.1R2")          fixes['14.1R'] = '14.1R2-S10';
else if (ver =~ "^14\.1R8")   fixes['14.1R'] = '14.1R8-S4';
else                          fixes['14.1R'] = '14.1R9';
fixes['14.1X53'] = '14.1X53-D45'; # or D122, D50

if (ver =~ "^14\.2R7")        fixes['14.2R'] = '14.2R7-S7';
else                          fixes['14.2R'] = '14.2R8';
if ( ver =~ "^15\.1F2")       fixes['15.1F'] = '15.1F2-S18';
else if ( ver =~ "^15\.1F6")  fixes['15.1F'] = '15.1F6-S7';

if (ver =~ "^15\.1R4")        fixes['15.1R'] = '15.1R4-S8';
else if (ver =~ "^15\.1R5")   fixes['15.1R'] = '15.1R5-S5';
else if (ver =~ "^15\.1R6")   fixes['15.1R'] = '15.1R6-S1';
else                          fixes['15.1R'] = '15.1R7';

fixes['15.1X49'] = '15.1X49-D100';
fixes['15.1X53'] = '15.1X53-D47'; # or D48/D57/D64/D70/D231

if (ver =~ "^16\.1R3")        fixes['16.1R'] = '16.1R3-S4';
else if (ver =~ "^16\.1R4")   fixes['16.1R'] = '16.1R4-S3'; # or S4
else                          fixes['16.1R'] = '16.1R5';
fixes['16.2'] = '16.2R2';

if (ver =~ "^17\.1R1")        fixes['17.1R'] = '17.1R1-S3';
else                          fixes['17.1R'] = '17.1R2';

if (ver =~ "^17\.2R1")        fixes['17.2R'] = '17.2R1-S1';
else                          fixes['17.2R'] = '17.2R2';
fixes['17.3'] = '17.3R1';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

junos_report(ver:ver, fix:fix, severity:SECURITY_HOLE);
