#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154111);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/13");

  script_cve_id("CVE-2021-31353");
  script_xref(name:"JSA", value:"JSA11218");
  script_xref(name:"IAVA", value:"2021-A-0478-S");

  script_name(english:"Juniper Junos OS Vulnerability (JSA11218)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA11218
advisory.

  - An Improper Handling of Exceptional Conditions vulnerability in Juniper Networks Junos OS and Junos OS
    Evolved allows an attacker to inject a specific BGP update, causing the routing protocol daemon (RPD) to
    crash and restart, leading to a Denial of Service (DoS). Continued receipt and processing of the BGP
    update will create a sustained Denial of Service (DoS) condition. This issue affects very specific
    versions of Juniper Networks Junos OS: 19.3R3-S2; 19.4R3-S3; 20.2 versions 20.2R2-S3 and later, prior to
    20.2R3-S2; 20.3 versions 20.3R2 and later, prior to 20.3R3; 20.4 versions 20.4R2 and later, prior to
    20.4R3; 21.1 versions prior to 21.1R2. Juniper Networks Junos OS 20.1 is not affected by this issue. This
    issue also affects Juniper Networks Junos OS Evolved: All versions prior to 20.4R2-S3-EVO, 20.4R3-EVO;
    21.1-EVO versions prior to 21.1R2-EVO; 21.2-EVO versions prior to 21.2R2-EVO. (CVE-2021-31353)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11218");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11218");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31353");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/13");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');


var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'20.2', 'fixed_ver':'20.2R2-S3'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R2'},
  {'min_ver':'20.4', 'fixed_ver':'20.4R2'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
