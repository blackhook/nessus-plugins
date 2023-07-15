#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(118232);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/08");

  script_cve_id("CVE-2018-0048");
  script_bugtraq_id(105564);
  script_xref(name:"JSA", value:"JSA10882");

  script_name(english:"Juniper Junos Memory Exhaustion RDP DOS with JET support (JSA10882)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Junos device
is affected by a denial of service vulnerability due to a flaw with the
Routing Protocols Daemon with Juniper Extension Toolkit support. A
remote attacker could exhaust memory resources potentially causing the
device to become unavailable.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10882");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in
Juniper advisory JSA10882.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0048");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/19");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');

fixes = make_array();
# 17.2 versions prior to 17.2R1-S7, 17.2R2-S6, 17.2R3
if (ver =~ "^17\.2R1($|[^0-9])")      fixes['17.2R'] = '17.2R1-S7';
else if (ver =~ "^17\.2R2($|[^0-9])") fixes['17.2R'] = '17.2R2-S6';
else                                  fixes['17.2R'] = '17.2R3';

# 17.2X75 versions prior to 17.2X75-D102, 17.2X75-D110
fixes['17.2X75'] = '17.2X75-D102';

# 17.3 versions prior to 17.3R2-S4, 17.3R3
if (ver =~ "^17\.3R2($|[^0-9])") fixes['17.3R'] = '17.3R2-S4';
else                             fixes['17.3R'] = '17.3R3';

# 17.4 versions prior to 17.4R1-S5, 17.4R2
if (ver =~ "^17\.4R1($|[^0-9])") fixes['17.4R'] = '17.4R1-S5';
else                             fixes['17.4R'] = '17.4R2';

# 18.1 versions prior to 18.1R2-S3, 18.1R3
if (ver =~ "^18\.1R2($|[^0-9])") fixes['18.1R'] = '18.1R2-S3';
else                             fixes['18.1R'] = '18.1R3';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# No listed way to check for JET support
override = FALSE;

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
