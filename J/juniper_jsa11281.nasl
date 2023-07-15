#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156693);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/27");

  script_cve_id("CVE-2022-22175");
  script_xref(name:"JSA", value:"JSA11281");

  script_name(english:"Juniper Junos OS Vulnerability (JSA11281)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA11281
advisory.

  - An Improper Locking vulnerability in the SIP ALG of Juniper Networks Junos OS on MX Series and SRX Series
    allows an unauthenticated networked attacker to cause a flowprocessing daemon (flowd) crash and thereby a
    Denial of Service (DoS). Continued receipt of these specific packets will cause a sustained Denial of
    Service condition. This issue can occur in a scenario where the SIP ALG is enabled and specific SIP
    messages are being processed simultaneously. This issue affects: Juniper Networks Junos OS on MX Series
    and SRX Series 20.4 versions prior to 20.4R3-S1; 21.1 versions prior to 21.1R2-S2, 21.1R3; 21.2 versions
    prior to 21.2R1-S2, 21.2R2; 21.3 versions prior to 21.3R1-S1, 21.3R2. This issue does not affect Juniper
    Networks Junos OS versions prior to 20.4R1. (CVE-2022-22175)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11281");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11281");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22175");

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
if (model !~ "^(MX|SRX)")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'20.4', 'fixed_ver':'20.4R3-S1', 'model':'^(MX|SRX)'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R2-S2', 'model':'^(MX|SRX)', 'fixed_display':'21.1R2-S2, 21.1R3'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R1-S2', 'model':'^(MX|SRX)', 'fixed_display':'21.2R1-S2, 21.2R2'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R1-S1', 'model':'^(MX|SRX)', 'fixed_display':'21.3R1-S1, 21.3R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
