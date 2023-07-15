##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163604);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/08");

  script_cve_id("CVE-2022-22204");
  script_xref(name:"IAVA", value:"2022-A-0280");
  script_xref(name:"JSA", value:"JSA69708");

  script_name(english:"Juniper Junos OS DoS (JSA69708)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA69708
advisory.

  - An Improper Release of Memory Before Removing Last Reference vulnerability in the Session Initiation Protocol (SIP) 
    Application Layer Gateway (ALG) of Juniper Networks Junos OS allows unauthenticated network-based attacker to cause 
    a partial Denial of Service (DoS). On all MX and SRX platforms, if the SIP ALG is enabled, receipt of a specific 
    SIP packet will create a stale SIP entry. Sustained receipt of such packets will cause the SIP call table to 
    eventually fill up and cause a DoS for all SIP traffic. This issue affects Juniper Networks Junos OS on SRX Series 
    and MX Series: 20.4 versions prior to 20.4R3-S2; 21.1 versions prior to 21.1R3-S2; 21.2 versions prior to 21.2R2-S2; 
    21.2 versions prior to 21.2R3; 21.3 versions prior to 21.3R2; 21.4 versions prior to 21.4R2. This issue does not 
    affect Juniper Networks Junos OS versions prior to 20.4R1. (CVE-2022-22204)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA69708");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA69708");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22204");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/29");

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
if (model !~ "^(MX|SRX)")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':' 20.4R1', 'fixed_ver':'20.4R3-S2', 'model':'^(MX|SRX)'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R3-S2', 'model':'^(MX|SRX)'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R2-S2', 'model':'^(MX|SRX)'},
  {'min_ver':'21.2R3', 'fixed_ver':'21.2R3', 'model':'^(MX|SRX)'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R2', 'model':'^(MX|SRX)'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R2', 'model':'^(MX|SRX)'}
];

override = TRUE;
var buf = junos_command_kb_item(cmd:"show security alg status");

if (buf)
{
  var pattern = "^\s*SIP\s*:\s*Enabled";
  if (!preg(string:buf, pattern:pattern, multiline:TRUE))
    audit(AUDIT_HOST_NOT, 'affected because the SIP ALG is not enabled');
  override = FALSE;
}

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) 
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);