#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156676);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/31");

  script_cve_id("CVE-2022-22160");
  script_xref(name:"JSA", value:"JSA11268");
  script_xref(name:"IAVA", value:"2022-A-0028");

  script_name(english:"Juniper Junos OS Vulnerability (JSA11268)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA11268
advisory.

  - An Unchecked Error Condition vulnerability in the subscriber management daemon (smgd) of Juniper Networks
    Junos OS allows an unauthenticated adjacent attacker to cause a crash of and thereby a Denial of Service
    (DoS). In a subscriber management / broadband edge environment if a single session group configuration
    contains dual-stack and a pp0 interface, smgd will crash and restart every time a PPPoE client sends a
    specific message. This issue affects Juniper Networks Junos OS on MX Series: 16.1 version 16.1R1 and later
    versions prior to 18.4R3-S10; 19.1 versions prior to 19.1R2-S3, 19.1R3-S7; 19.2 versions prior to
    19.2R1-S8, 19.2R3-S4; 19.3 versions prior to 19.3R3-S4; 19.4 versions prior to 19.4R3-S5; 20.1 versions
    prior to 20.1R3-S3; 20.2 versions prior to 20.2R3-S3; 20.3 versions prior to 20.3R3-S2; 20.4 versions
    prior to 20.4R3; 21.1 versions prior to 21.1R3; 21.2 versions prior to 21.2R2. This issue does not affect
    Juniper Networks Junos OS versions prior to 16.1R1. (CVE-2022-22160)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11268");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11268");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22160");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/12");

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
if (model !~ "^MX")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'16.1', 'fixed_ver':'16.1R1', 'model':'^MX'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R2-S3', 'model':'^MX'},
  {'min_ver':'19.1R3', 'fixed_ver':'19.1R3-S7', 'model':'^MX'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R1-S8', 'model':'^MX'},
  {'min_ver':'19.2R2', 'fixed_ver':'19.2R3-S4', 'model':'^MX'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R3-S4', 'model':'^MX'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R3-S5', 'model':'^MX'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R3-S3', 'model':'^MX'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R3-S3', 'model':'^MX'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R3-S2', 'model':'^MX'},
  {'min_ver':'20.4', 'fixed_ver':'20.4R3', 'model':'^MX'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R3', 'model':'^MX'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R2', 'model':'^MX'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_NOTE, port:0, extra:report);
