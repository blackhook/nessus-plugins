##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163461);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/08");

  script_cve_id("CVE-2022-22221");
  script_xref(name:"JSA", value:"JSA69725");
  script_xref(name:"IAVA", value:"2022-A-0280");

  script_name(english:"Juniper Junos Local Privilege Escalation Vulnerability (JSA69725)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"An Improper Neutralization of Special Elements vulnerability in the download manager of Juniper Networks Junos OS
allows a locally authenticated attacker with low privileges to take full control over the device.
 
A workaround would be to deny users access to the 'request system download ...' and 'show system download ...' CLI
commands.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA69725");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA69725");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22221");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/26");

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

var model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ "^(SRX|EX)")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'19.2', 'fixed_ver':'19.2R1-S9', 'fixed_display':'19.2R1-S9, 19.2R3-S5'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R3-S6'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R3-S8'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R3-S4'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R3-S4'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R3-S3'},
  {'min_ver':'20.4', 'fixed_ver':'20.4R3-S2', 'fixed_display':'20.4R3-S2, 20.4R3-S3'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R3-S1'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R2-S2', 'fixed_display':'21.2R2-S2, 21.2R'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R2', 'fixed_display':'21.3R2, 21.3R3'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R1-S1', 'fixed_display':'21.4R1-S1, 21.4R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
