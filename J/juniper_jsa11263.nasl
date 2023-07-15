#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156683);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/27");

  script_cve_id("CVE-2022-22155");
  script_xref(name:"JSA", value:"JSA11263");

  script_name(english:"Juniper Junos OS Vulnerability (JSA11263)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA11263
advisory.

  - An Uncontrolled Resource Consumption vulnerability in the handling of IPv6 neighbor state change events in
    Juniper Networks Junos OS allows an adjacent attacker to cause a memory leak in the Flexible PIC
    Concentrator (FPC) of an ACX5448 router. The continuous flapping of an IPv6 neighbor with specific timing
    will cause the FPC to run out of resources, leading to a Denial of Service (DoS) condition. Once the
    condition occurs, further packet processing will be impacted, creating a sustained Denial of Service (DoS)
    condition, requiring a manual PFE restart to restore service. The following error messages will be seen
    after the FPC resources have been exhausted: fpc0 DNX_NH::dnx_nh_tag_ipv4_hw_install(),3135:
    dnx_nh_tag_ipv4_hw_install: BCM L3 Egress create object failed for NH 602 (-14:No resources for
    operation), BCM NH Params: unit:0 Port:41, L3_INTF:0 Flags: 0x40 fpc0
    DNX_NH::dnx_nh_tag_ipv4_hw_install(),3135: dnx_nh_tag_ipv4_hw_install: BCM L3 Egress create object failed
    for NH 602 (-14:No resources for operation), BCM NH Params: unit:0 Port:41, L3_INTF:0 Flags: 0x40 fpc0
    DNX_NH::dnx_nh_tag_ipv4_hw_install(),3135: dnx_nh_tag_ipv4_hw_install: BCM L3 Egress create object failed
    for NH 602 (-14:No resources for operation), BCM NH Params: unit:0 Port:41, L3_INTF:0 Flags: 0x40 fpc0
    DNX_NH::dnx_nh_tag_ipv4_hw_install(),3135: dnx_nh_tag_ipv4_hw_install: BCM L3 Egress create object failed
    for NH 602 (-14:No resources for operation), BCM NH Params: unit:0 Port:41, L3_INTF:0 Flags: 0x40 This
    issue only affects the ACX5448 router. No other products or platforms are affected by this vulnerability.
    This issue affects Juniper Networks Junos OS on ACX5448: 18.4 versions prior to 18.4R3-S10; 19.1 versions
    prior to 19.1R3-S5; 19.2 versions prior to 19.2R1-S8, 19.2R3-S2; 19.3 versions prior to 19.3R2-S6,
    19.3R3-S2; 19.4 versions prior to 19.4R1-S3, 19.4R2-S2, 19.4R3; 20.1 versions prior to 20.1R2; 20.2
    versions prior to 20.2R1-S1, 20.2R2. (CVE-2022-22155)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11263");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11263");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22155");

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
if (model !~ "^ACX5448")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'18.4', 'fixed_ver':'18.4R3-S10', 'model':'^ACX5448'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R3-S5', 'model':'^ACX5448'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R1-S8', 'model':'^ACX5448'},
  {'min_ver':'19.2R2', 'fixed_ver':'19.2R3-S2', 'model':'^ACX5448'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R2-S6', 'model':'^ACX5448'},
  {'min_ver':'19.3R3', 'fixed_ver':'19.3R3-S2', 'model':'^ACX5448'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R1-S3', 'model':'^ACX5448', 'fixed_display':'19.4R1-S3, 19.4R2-S2, 19.4R3'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R2', 'model':'^ACX5448'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R1-S1', 'model':'^ACX5448', 'fixed_display':'20.2R1-S1, 20.2R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_NOTE, port:0, extra:report);
