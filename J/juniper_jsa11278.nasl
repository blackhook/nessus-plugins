#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156674);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/03");

  script_cve_id("CVE-2022-22172");
  script_xref(name:"JSA", value:"JSA11278");
  script_xref(name:"IAVA", value:"2022-A-0028");

  script_name(english:"Juniper Junos OS Vulnerability (JSA11278)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA11278
advisory.

  - A Missing Release of Memory after Effective Lifetime vulnerability in the Layer-2 control protocols daemon
    (l2cpd) of Juniper Networks Junos OS and Junos OS Evolved allows an unauthenticated adjacent attacker to
    cause a memory leak. Continued exploitation can lead to memory exhaustion and thereby a Denial of Service
    (DoS). This issue occurs when specific LLDP packets are received. The impact of the l2cpd cores is that if
    any of the stp protocols (rstp, mstp or vstp) is used then stp re-converges and traffic loss will occur
    during that time. Also if any services depend on LLDP state (like PoE or VoIP device recognition) then
    these will also be affected. The memory utilization of the L2CPd process can be monitored with the
    following command: user@host> show system processes extensive | match l2cpd 1234 root 52 0 521M 43412K RUN
    1 4:02 34.47% l2cpd This issue affects: Juniper Networks Junos OS 18.4 version 18.4R2-S4 and later
    versions prior to 18.4R2-S10. 19.2 versions prior to 19.2R1-S8, 19.2R3-S4; 19.3 versions prior to
    19.3R3-S5; 19.4 versions prior to 19.4R3-S7; 20.1 versions prior to 20.1R3-S3; 20.2 versions prior to
    20.2R3-S2; 20.3 versions prior to 20.3R3-S1; 20.4 versions prior to 20.4R3; 21.1 versions prior to
    21.1R2-S2, 21.1R3; 21.2 versions prior to 21.2R2; Juniper Networks Junos OS Evolved All versions prior to
    20.4R3-S2-EVO; 21.1 version 21.1R1-EVO and later versions; 21.2 versions prior to 21.2R2-EVO. This issue
    does not affect: Juniper Networks Junos OS 19.1 version 19.1R1 and later versions. (CVE-2022-22172)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11278");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11278");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22172");

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
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');


var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'18.4', 'fixed_ver':'18.4R2-S4'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R1-S8'},
  {'min_ver':'19.2R2', 'fixed_ver':'19.2R3-S4'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R3-S5'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R3-S7'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R3-S3'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R3-S2'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R3-S1'},
  {'min_ver':'20.4', 'fixed_ver':'20.4R3'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R1-EVO', 'fixed_display':'21.1R1-EVO, 21.1R2-S2, 21.1R3'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R2', 'fixed_display':'21.2R2, 21.2R2-EVO'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_NOTE, port:0, extra:report);
