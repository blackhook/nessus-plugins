#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106391);
  script_version("1.5");
  script_cvs_date("Date: 2018/07/13 15:08:46");

  script_cve_id("CVE-2018-0006");
  script_xref(name:"JSA", value:"JSA10834");

  script_name(english:"Juniper Junos VLAN authentication processing DoS (JSA10834)");
  script_summary(english:"Checks the Junos version and build date.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Junos device
is affected by a denial of service vulnerability.");
  # https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10834&actp=METADATA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4ec45d85");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in
Juniper advisory JSA10834.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
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
# 15.1 versions prior to 15.1R6-S2, 15.1R7
# 16.1 versions prior to 16.1R5-S1, 16.1R6
# 16.2 versions prior to 16.2R2-S2, 16.2R3
# 17.1 versions prior to 17.1R2-S5, 17.1R3
# 17.2 versions prior to 17.2R2
fixes = make_array();
if (ver =~ "^15\.1R6")
  fixes['15.1'] = '15.1R6-S2';
else
  fixes['15.1'] = '15.1R7';
if (ver =~ "^16\.1R5")
  fixes['16.1'] = '16.1R5-S1';
else
  fixes['16.1'] = '16.1R6';
if (ver =~ "^16\.2R2")
  fixes['16.2'] = '16.2R2-S2';
else
  fixes['16.2'] = '16.2R3';
if (ver =~ "^17\.1R2")
  fixes['17.1'] = '17.1R2-S5';
else
  fixes['17.1'] = '17.1R3';
fixes['17.2'] = '17.2R2';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

override = FALSE;

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
