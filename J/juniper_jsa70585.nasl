#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174255);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/21");

  script_cve_id("CVE-2023-28960");
  script_xref(name:"JSA", value:"JSA70585");
  script_xref(name:"IAVA", value:"2023-A-0201");

  script_name(english:"Juniper Junos OS Vulnerability (JSA70585)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA70585
advisory.

  - An Incorrect Permission Assignment for Critical Resource vulnerability in Juniper Networks Junos OS
    Evolved allows a local, authenticated low-privileged attacker to copy potentially malicious files into an
    existing Docker container on the local system. A follow-on administrator could then inadvertently start
    the Docker container leading to the malicious files being executed as root. (CVE-2023-28960)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/Overview-of-the-Juniper-Networks-SIRT-Quarterly-Security-Bulletin-Publication-Process
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?99086ea4");
  # https://supportportal.juniper.net/s/article/In-which-releases-are-vulnerabilities-fixed
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b616ed59");
  # https://supportportal.juniper.net/s/article/Common-Vulnerability-Scoring-System-CVSS-and-Juniper-s-Security-Advisories
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d4fd08b");
  # https://supportportal.juniper.net/s/article/2023-04-Security-Bulletin-Junos-OS-Evolved-Docker-repository-is-world-writeable-allowing-low-privileged-local-user-to-inject-files-into-Docker-containers-CVE-2023-28960
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fbdf9ef9");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA70585");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-28960");

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
  {'min_ver':'20.4', 'fixed_ver':'20.4R3-S5-EVO'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R3-EVO'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R3-EVO'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R2-EVO'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
