##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161299);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/19");

  script_cve_id("CVE-2022-22183");
  script_xref(name:"JSA", value:"JSA69516");
  script_xref(name:"IAVA", value:"2022-A-0162");

  script_name(english:"Juniper Junos OS Evolved DoS (JSA69516)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"An Improper Access Control vulnerability in Juniper Networks Junos OS Evolved allows a network-based unauthenticated 
attacker who is able to connect to a specific open IPv4 port, which in affected releases should otherwise be 
unreachable, to cause the CPU to consume all resources as more traffic is sent to the port to create a denial of 
service (DoS) condition. Continued receipt and processing of these packets will create a sustained denial of service 
(DoS) condition. This issue affects: Juniper Networks Junos OS Evolved 20.4 versions prior to 20.4R3-S2-EVO; 21.1 
versions prior to 21.1R3-S1-EVO; 21.2 versions prior to 21.2R3-EVO; 21.3 versions prior to 21.3R2-EVO; 21.4 versions 
prior to 21.4R2-EVO. This issue does not affect Junos OS.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA69516");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA69516");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22183");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/18");

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
  {'min_ver':'20.4', 'fixed_ver':'20.4R3-S2-EVO'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R3-S1-EVO'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R3-EVO'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R2-EVO'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R2-EVO'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
