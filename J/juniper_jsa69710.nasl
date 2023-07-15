##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(164019);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id("CVE-2022-22206");
  script_xref(name:"JSA", value:"JSA69710");
  script_xref(name:"IAVA", value:"2022-A-0280");

  script_name(english:"Juniper Junos DOS (JSA10928)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"A Buffer Overflow vulnerability in the PFE of Juniper Networks Junos OS on SRX series allows an unauthenticated 
network based attacker to cause a Denial of Service (DoS). The PFE will crash when specific traffic is scanned by 
Enhanced Web Filtering safe-search feature of UTM (Unified Threat management). Continued receipt of this specific 
traffic will create a sustained Denial of Service (DoS) condition, 

Note that Nessus has not tested for this issue but has instead relied only on
the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA69710");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper
advisory JSA69710");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22206");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/10");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

var model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ "^(SRX)")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'20.2', 'fixed_ver':'20.2R3-S4', 'model':'^(SRX)'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R3-S3', 'model':'^(SRX)'},
  {'min_ver':'20.4', 'fixed_ver':'20.4R3-S3', 'model':'^(SRX)'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R3-S1', 'model':'^(SRX)'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R2-S2', 'model':'^(SRX)', 'fixed_display':'21.2R2-S2, 21.2R3'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R2', 'model':'^(SRX)'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R2', 'model':'^(SRX)'}
];

var override = TRUE;
var pattern;
var buf = junos_command_kb_item(cmd:'show security utm');
if (buf)
{
  override = FALSE;
  pattern = "^.*default-configuration.*web-filtering.*juniper-enhanced.*no-safe-search";
  if (junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_OS_CONF_NOT_VULN, 'Junos OS');

  pattern = "^feature-profile.*web-filtering.*juniper-enhanced.*profile.*no-safe-search";
  if (junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_OS_CONF_NOT_VULN, 'Junos OS'); 
}

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) 
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);