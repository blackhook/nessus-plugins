#%NASL_MIN_LEVEL 80900
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174625);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

  script_cve_id("CVE-2023-28961");
  script_xref(name:"JSA", value:"JSA70586");
  script_xref(name:"IAVA", value:"2023-A-0201");

  script_name(english:"Juniper Junos OS Vulnerability (JSA70586)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA70586
advisory.

  - An Improper Handling of Unexpected Data Type vulnerability in IPv6 firewall filter processing of Juniper Networks 
    Junos OS on the ACX Series devices will prevent a firewall filter with the term from next-header ah from being 
    properly installed in the packet forwarding engine (PFE). There is no immediate indication of an incomplete firewall
    filter commit shown at the CLI, which could allow an attacker to send valid packets to or through the device that were 
    explicitly intended to be dropped. This issue affects Juniper Networks Junos OS on ACX Series: All versions prior to 
    20.2R3-S7; 20.4 versions prior to 20.4R3-S4; 21.1 versions prior to 21.1R3-S3; 21.2 versions prior to 21.2R3-S4; 
    21.3 versions prior to 21.3R3; 21.4 versions prior to 21.4R3; 22.1 versions prior to 22.1R2. (CVE-2023-28961)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA70586");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA70586");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-28961");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');

var model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ "^ACX")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'1.0',  'fixed_ver':'20.2R3-S7', 'model':'^ACX'},
  {'min_ver':'20.4', 'fixed_ver':'20.4R3-S4', 'model':'^ACX'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R3-S3', 'model':'^ACX'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R3-S4', 'model':'^ACX'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R3', 'model':'^ACX'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R3', 'model':'^ACX'},
  {'min_ver':'22.1', 'fixed_ver':'22.1R2', 'model':'^ACX'},
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
