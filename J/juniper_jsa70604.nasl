#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174248);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/21");

  script_cve_id("CVE-2023-28979");
  script_xref(name:"JSA", value:"JSA70604");
  script_xref(name:"IAVA", value:"2023-A-0201");

  script_name(english:"Juniper Junos OS Vulnerability (JSA70604)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA70604
advisory.

  - An Improper Check for Unusual or Exceptional Conditions vulnerability in the kernel of Juniper Networks
    Junos OS allows an adjacent unauthenticated attacker to bypass an integrity check. (CVE-2023-28979)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/Overview-of-the-Juniper-Networks-SIRT-Quarterly-Security-Bulletin-Publication-Process
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?99086ea4");
  # https://supportportal.juniper.net/s/article/In-which-releases-are-vulnerabilities-fixed
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b616ed59");
  # https://supportportal.juniper.net/s/article/Common-Vulnerability-Scoring-System-CVSS-and-Juniper-s-Security-Advisories
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d4fd08b");
  # https://supportportal.juniper.net/s/article/2023-04-Security-Bulletin-Junos-OS-In-a-6PE-scenario-upon-receipt-of-a-specific-IPv6-packet-an-integrity-check-fails-CVE-2023-28979
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9e5b0267");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA70604");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-28979");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/13");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');


var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'19.4', 'fixed_ver':'19.4R3-S9'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R3-S7'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R3-S5'},
  {'min_ver':'20.4', 'fixed_ver':'20.4R3-S4'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R3-S3'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R3-S2'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R3-S1'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R2-S1', 'fixed_display':'21.4R2-S1, 21.4R3'},
  {'min_ver':'22.1', 'fixed_ver':'22.1R2'},
  {'min_ver':'22.2', 'fixed_ver':'22.2R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_NOTE, port:0, extra:report);
