##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161775);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/03");

  script_cve_id("CVE-2021-31373");
  script_xref(name:"JSA", value:"JSA11238");

  script_name(english:"Juniper Junos OS Vulnerability (JSA11238)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"A persistent Cross-Site Scripting (XSS) vulnerability in Juniper Networks Junos OS on SRX Series, J-Web interface may 
allow a remote authenticated user to inject persistent and malicious scripts. An attacker can exploit this 
vulnerability to steal sensitive data and credentials from a web administration session, or hijack another user's 
active session to perform administrative actions. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11238");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11238");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31373");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/02");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
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
if (model !~ "^(SRX)")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'18.2', 'fixed_ver':'18.2R3-S8', 'model':'^(SRX)'},
  {'min_ver':'18.3', 'fixed_ver':'18.3R3-S5', 'model':'^(SRX)'},
  {'min_ver':'18.4', 'fixed_ver':'18.4R3-S8', 'model':'^(SRX)'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R3-S5', 'model':'^(SRX)'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R1-S7', 'model':'^(SRX)', 'fixed_display':'19.2R1-S7, 19.2R3-S3'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R2-S6', 'model':'^(SRX)', 'fixed_display':'19.3R2-S6, 19.3R3-S3'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R1-S4', 'model':'^(SRX)', 'fixed_display':'19.4R1-S4, 19.4R2-S4, 19.4R3-S3'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R2-S2', 'model':'^(SRX)', 'fixed_display':'20.1R2-S2, 20.1R3'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R3-S1', 'model':'^(SRX)'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R2-S1', 'model':'^(SRX)', 'fixed_display':'20.3R2-S1, 20.3R3'}
];

var override = TRUE;
var buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  if (!junos_check_config(buf:buf, pattern:"^set system services web-management"))
    audit(AUDIT_OS_CONF_NOT_VULN, 'Junos OS');
}

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) 
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_NOTE, xss:TRUE);
