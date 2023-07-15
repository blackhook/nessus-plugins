#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156680);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/31");

  script_cve_id("CVE-2022-22157", "CVE-2022-22167");
  script_xref(name:"JSA", value:"JSA11265");

  script_name(english:"Juniper Junos OS Multiple Vulnerabilities (JSA11265)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by multiple vulnerabilities as referenced in the
JSA11265 advisory.

  - A traffic classification vulnerability in Juniper Networks Junos OS on the SRX Series Services Gateways
    may allow an attacker to bypass Juniper Deep Packet Inspection (JDPI) rules and access unauthorized
    networks or resources, when 'no-syn-check' is enabled on the device. While JDPI correctly classifies out-
    of-state asymmetric TCP flows as the dynamic-application UNKNOWN, this classification is not provided to
    the policy module properly and hence traffic continues to use the pre-id-default-policy, which is more
    permissive, causing the firewall to allow traffic to be forwarded that should have been denied. This issue
    only occurs when 'set security flow tcp-session no-syn-check' is configured on the device. This issue
    affects Juniper Networks Junos OS on SRX Series: 18.4 versions prior to 18.4R2-S10, 18.4R3-S10; 19.1
    versions prior to 19.1R3-S8; 19.2 versions prior to 19.2R1-S8, 19.2R3-S4; 19.3 versions prior to
    19.3R3-S3; 19.4 versions prior to 19.4R3-S5; 20.1 versions prior to 20.1R3-S1; 20.2 versions prior to
    20.2R3-S2; 20.3 versions prior to 20.3R3-S1; 20.4 versions prior to 20.4R2-S2, 20.4R3; 21.1 versions prior
    to 21.1R2-S2, 21.1R3; 21.2 versions prior to 21.2R2. This issue does not affect Juniper Networks Junos OS
    versions prior to 18.4R1. (CVE-2022-22167)

  - A traffic classification vulnerability in Juniper Networks Junos OS on the SRX Series Services Gateways
    may allow an attacker to bypass Juniper Deep Packet Inspection (JDPI) rules and access unauthorized
    networks or resources, when 'no-syn-check' is enabled on the device. JDPI incorrectly classifies out-of-
    state asymmetric TCP flows as the dynamic-application INCONCLUSIVE instead of UNKNOWN, which is more
    permissive, causing the firewall to allow traffic to be forwarded that should have been denied. This issue
    only occurs when 'set security flow tcp-session no-syn-check' is configured on the device. This issue
    affects Juniper Networks Junos OS on SRX Series: 18.4 versions prior to 18.4R2-S9, 18.4R3-S9; 19.1
    versions prior to 19.1R2-S3, 19.1R3-S6; 19.2 versions prior to 19.2R1-S7, 19.2R3-S3; 19.3 versions prior
    to 19.3R2-S6, 19.3R3-S2; 19.4 versions prior to 19.4R2-S5, 19.4R3-S3; 20.1 versions prior to 20.1R2-S2,
    20.1R3; 20.2 versions prior to 20.2R3-S1; 20.3 versions prior to 20.3R3; 20.4 versions prior to 20.4R2-S1,
    20.4R3; 21.1 versions prior to 21.1R1-S1, 21.1R2. This issue does not affect Juniper Networks Junos OS
    versions prior to 18.4R1. (CVE-2022-22157)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11265");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11265");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22167");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/12");

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

var model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ "^SRX")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'18.4', 'fixed_ver':'18.4R2-S10', 'model':'^SRX'},
  {'min_ver':'18.4R3', 'fixed_ver':'18.4R3-S10', 'model':'^SRX'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R3-S8', 'model':'^SRX'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R1-S8', 'model':'^SRX'},
  {'min_ver':'19.2R2', 'fixed_ver':'19.2R3-S4', 'model':'^SRX'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R3-S3', 'model':'^SRX'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R3-S5', 'model':'^SRX'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R3-S1', 'model':'^SRX'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R3-S2', 'model':'^SRX'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R3-S1', 'model':'^SRX'},
  {'min_ver':'20.4', 'fixed_ver':'20.4R2-S2', 'model':'^SRX', 'fixed_display':'20.4R2-S2, 20.4R3'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R2-S2', 'model':'^SRX', 'fixed_display':'21.1R2-S2, 21.1R3'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R2', 'model':'^SRX'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
