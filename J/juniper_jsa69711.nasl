#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(164897);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2022-22207");
  script_xref(name:"JSA", value:"JSA69711");
  script_xref(name:"IAVA", value:"2022-A-0280");

  script_name(english:"Juniper Junos OS DOS (JSA69711)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA69711
advisory.

A Use After Free vulnerability in the Advanced Forwarding Toolkit (AFT) manager process (aftmand) of Juniper Networks 
Junos OS allows an unauthenticated networked attacker to cause a kernel crash due to intensive polling of Abstracted 
Fabric (AF) interface statistics and thereby a Denial of Service (DoS). Continued gathering of AF interface statistics 
will create a sustained Denial of Service (DoS) condition

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA69711");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA69711");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22207");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/09");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

var model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ "^MX")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'20.1.R1', 'fixed_ver':'20.1R3-S3', 'model':'^MX'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R3-S5', 'model':'^MX'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R3-S4', 'model':'^MX'},
  {'min_ver':'20.4', 'fixed_ver':'20.4R3', 'model':'^MX'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R2', 'model':'^MX'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R2', 'model':'^MX'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);

var override = TRUE;
var buf = junos_command_kb_item(cmd:'edit chassis');
if (buf)
{
  override = FALSE;
  if (!preg(string:buf, pattern:"^network-slices", multiline:TRUE))
    audit(AUDIT_OS_CONF_NOT_VULN, 'Junos OS');
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);