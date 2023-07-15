#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156681);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/24");

  script_cve_id("CVE-2022-22159");
  script_xref(name:"JSA", value:"JSA11267");

  script_name(english:"Juniper Junos OS Vulnerability (JSA11267)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA11267
advisory.

  - A vulnerability in the NETISR network queue functionality of Juniper Networks Junos OS kernel allows an
    attacker to cause a Denial of Service (DoS) by sending crafted genuine packets to a device. During an
    attack, the routing protocol daemon (rpd) CPU may reach 100% utilization, yet FPC CPUs forwarding traffic
    will operate normally. This attack occurs when the attackers' packets are sent over an IPv4 unicast
    routing equal-cost multi-path (ECMP) unilist selection. Continued receipt and processing of these packets
    will create a sustained Denial of Service (DoS) condition. An indicator of compromise may be to monitor
    NETISR drops in the network with the assistance of JTAC. Please contact JTAC for technical support for
    further guidance. This issue affects: Juniper Networks Junos OS 17.3 version 17.3R3-S9 and later versions
    prior to 17.3R3-S12; 17.4 version 17.4R3-S3 and later versions prior to 17.4R3-S5; 18.1 version 18.1R3-S11
    and later versions prior to 18.1R3-S13; 18.2 version 18.2R3-S6 and later versions; 18.3 version 18.3R3-S4
    and later versions prior to 18.3R3-S5; 18.4 version 18.4R3-S5 and later versions prior to 18.4R3-S9; 19.1
    version 19.1R3-S3 and later versions prior to 19.1R3-S7. This issue does not affect Juniper Networks Junos
    OS versions prior to 17.3R3-S9. This issue does not affect Juniper Networks Junos OS Evolved.
    (CVE-2022-22159)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11267");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11267");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22159");

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
  {'min_ver':'17.3', 'fixed_ver':'17.3R3-S9'},
  {'min_ver':'17.4', 'fixed_ver':'17.4R3-S3'},
  {'min_ver':'18.1', 'fixed_ver':'18.1R3-S11'},
  {'min_ver':'18.2', 'fixed_ver':'18.2R3-S6'},
  {'min_ver':'18.3', 'fixed_ver':'18.3R3-S4'},
  {'min_ver':'18.4', 'fixed_ver':'18.4R3-S5'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R3-S3'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
