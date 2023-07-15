#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102077);
  script_version ("1.3");
  script_cvs_date("Date: 2018/07/12 19:01:16");

  script_cve_id("CVE-2017-10601");
  script_xref(name:"JSA", value:"JSA10802");

  script_name(english:"Juniper Junos User Authentication Bypass (JSA10802)");
  script_summary(english:"Checks the Junos version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by an authentication bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by an authentication bypass vulnerability due
to a specific device configuration that can result in a commit failure
condition, which allows a user to be logged in without being prompted
for a password. A remote attacker can exploit this issue to bypass
authentication on the device.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10802");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant Junos software release referenced in Juniper
security advisory JSA10802.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/31");

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

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

fixes = make_array();

fixes['12.3']    = '12.3R10';
fixes['12.3X48'] = '12.3X48-D20';
fixes['13.2']    = '13.2R8';
fixes['13.3']    = '13.3R7';
fixes['14.1']    = '14.1R4-S12';
fixes['14.1X53'] = '14.1X53-D30';
fixes['14.2']    = '14.2R4';
fixes['15.1']    = '15.1R2';
fixes['15.1X49'] = '15.1X49-D10';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

junos_report(ver:ver, fix:fix, severity:SECURITY_HOLE);
