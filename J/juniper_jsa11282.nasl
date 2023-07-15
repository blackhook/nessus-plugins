#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156670);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/27");

  script_cve_id("CVE-2022-22176");
  script_xref(name:"JSA", value:"JSA11282");

  script_name(english:"Juniper Junos OS Vulnerability (JSA11282)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA11282
advisory.

  - An Improper Validation of Syntactic Correctness of Input vulnerability in the Juniper DHCP daemon (jdhcpd)
    of Juniper Networks Junos OS allows an adjacent unauthenticated attacker sending a malformed DHCP packet
    to cause a crash of jdhcpd and thereby a Denial of Service (DoS). If option-82 is configured in a DHCP
    snooping / -security scenario, jdhcpd crashes if a specific malformed DHCP request packet is received. The
    DHCP functionality is impacted while jdhcpd restarts, and continued exploitation of the vulnerability will
    lead to the unavailability of the DHCP service and thereby a sustained DoS. This issue affects Juniper
    Networks Junos OS 13.2 version 13.2R1 and later versions prior to 15.1R7-S11; 18.3 versions prior to
    18.3R3-S6; 18.4 versions prior to 18.4R2-S9, 18.4R3-S10; 19.1 versions prior to 19.1R2-S3, 19.1R3-S7; 19.2
    versions prior to 19.2R1-S8, 19.2R3-S4; 19.3 versions prior to 19.3R2-S7, 19.3R3-S4; 19.4 versions prior
    to 19.4R3-S6; 20.1 versions prior to 20.1R3-S3; 20.2 versions prior to 20.2R3-S3; 20.3 versions prior to
    20.3R3-S1; 20.4 versions prior to 20.4R3; 21.1 versions prior to 21.1R2-S1, 21.1R3; 21.2 versions prior to
    21.2R1-S1, 21.2R2. This issue does not affect Juniper Networks Junos OS version 12.3R12 and prior
    versions. (CVE-2022-22176)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11282");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11282");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22176");

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
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');


var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'13.2', 'fixed_ver':'13.2R1'},
  {'min_ver':'18.3', 'fixed_ver':'18.3R3-S6'},
  {'min_ver':'18.4', 'fixed_ver':'18.4R2-S9'},
  {'min_ver':'18.4R3', 'fixed_ver':'18.4R3-S10'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R2-S3'},
  {'min_ver':'19.1R3', 'fixed_ver':'19.1R3-S7'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R1-S8'},
  {'min_ver':'19.2R2', 'fixed_ver':'19.2R3-S4'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R2-S7'},
  {'min_ver':'19.3R3', 'fixed_ver':'19.3R3-S4'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R3-S6'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R3-S3'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R3-S3'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R3-S1'},
  {'min_ver':'20.4', 'fixed_ver':'20.4R3'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R2-S1', 'fixed_display':'21.1R2-S1, 21.1R3'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R1-S1', 'fixed_display':'21.2R1-S1, 21.2R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_NOTE, port:0, extra:report);
