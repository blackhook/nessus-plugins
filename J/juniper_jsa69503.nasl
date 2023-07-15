#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160183);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/13");

  script_cve_id("CVE-2022-22193");
  script_xref(name:"JSA", value:"JSA69503");
  script_xref(name:"IAVA", value:"2022-A-0162");

  script_name(english:"Juniper Junos OS Vulnerability (JSA69503)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA69503
advisory.

  - An Improper Handling of Unexpected Data Type vulnerability in the Routing Protocol Daemon (rpd) of Juniper
    Networks Junos OS and Junos OS Evolved allows a locally authenticated attacker with low privileges to
    cause a Denial of Service (DoS). Continued execution of this command might cause a sustained Denial of
    Service condition. If BGP rib sharding is configured and a certain CLI command is executed the rpd process
    can crash. During the rpd crash and restart, the routing protocols might be impacted and traffic
    disruption might be seen due to the loss of routing information. This issue affects: Juniper Networks
    Junos OS 20.3 versions prior to 20.3R3-S1; 20.4 versions prior to 20.4R3; 21.1 versions prior to 21.1R3;
    21.2 versions prior to 21.2R2. Juniper Networks Junos OS Evolved 20.4 versions prior to 20.4R3-EVO; 21.1
    versions prior to 21.1R3-EVO; 21.2 versions prior to 21.2R2-EVO. This issue does not affect: Juniper
    Networks Junos OS versions prior to 20.3R1. Juniper Networks Junos OS Evolved versions prior to
    20.3R1-EVO. (CVE-2022-22193)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/Overview-of-the-Juniper-Networks-SIRT-Quarterly-Security-Bulletin-Publication-Process
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?99086ea4");
  # https://supportportal.juniper.net/s/article/In-which-releases-are-vulnerabilities-fixed
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b616ed59");
  # https://supportportal.juniper.net/s/article/Common-Vulnerability-Scoring-System-CVSS-and-Juniper-s-Security-Advisories
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d4fd08b");
  # https://supportportal.juniper.net/s/article/2022-04-Security-Bulletin-Junos-OS-and-Junos-OS-Evolved-In-a-BGP-rib-sharding-scenario-when-a-certain-CLI-command-is-executed-the-rpd-process-might-crash-CVE-2022-22193
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?78f80529");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA69503");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22193");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/25");

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
  {'min_ver':'20.3', 'fixed_ver':'20.3R3-S1'},
  {'min_ver':'20.4', 'fixed_ver':'20.4R3', 'fixed_display':'20.4R3, 20.4R3-EVO'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R3', 'fixed_display':'21.1R3, 21.1R3-EVO'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R2', 'fixed_display':'21.2R2, 21.2R2-EVO'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
