#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154117);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/13");

  script_cve_id("CVE-2021-31376");
  script_xref(name:"JSA", value:"JSA11241");
  script_xref(name:"IAVA", value:"2021-A-0478-S");

  script_name(english:"Juniper Junos OS Vulnerability (JSA11241)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA11241
advisory.

  - An Improper Input Validation vulnerability in Packet Forwarding Engine manager (FXPC) process of Juniper
    Networks Junos OS allows an attacker to cause a Denial of Service (DoS) by sending specific DHCPv6 packets
    to the device and crashing the FXPC service. Continued receipt and processing of this specific packet will
    create a sustained Denial of Service (DoS) condition. This issue affects only the following platforms in
    ACX Series: ACX500, ACX1000, ACX1100, ACX2100, ACX2200, ACX4000, ACX5048, ACX5096 devices. Other ACX
    platforms are not affected from this issue. This issue affects Juniper Networks Junos OS on ACX500,
    ACX1000, ACX1100, ACX2100, ACX2200, ACX4000, ACX5048, ACX5096: 18.4 version 18.4R3-S7 and later versions
    prior to 18.4R3-S8. This issue does not affect: Juniper Networks Junos OS 18.4 versions prior to 18.4R3-S7
    on ACX500, ACX1000, ACX1100, ACX2100, ACX2200, ACX4000, ACX5048, ACX5096. (CVE-2021-31376)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11241");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11241");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31376");

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
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');

var model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ "^(ACX1000|ACX1100|ACX2100|ACX2200|ACX4000|ACX500|ACX5048|ACX5096)")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'18.4', 'fixed_ver':'18.4R3-S7', 'model':'^(ACX1000|ACX1100|ACX2100|ACX2200|ACX4000|ACX500|ACX5048|ACX5096)'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
