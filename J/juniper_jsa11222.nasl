#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154126);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/13");

  script_cve_id("CVE-2021-31359", "CVE-2021-31360");
  script_xref(name:"JSA", value:"JSA11222");
  script_xref(name:"IAVA", value:"2021-A-0478-S");

  script_name(english:"Juniper Junos OS Multiple Vulnerabilities (JSA11222)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by multiple vulnerabilities as referenced in the
JSA11222 advisory.

  - A local privilege escalation vulnerability in Juniper Networks Junos OS and Junos OS Evolved allows a
    local, low-privileged user to cause the Juniper DHCP daemon (jdhcpd) process to crash, resulting in a
    Denial of Service (DoS), or execute arbitrary commands as root. Continued processing of malicious input
    will repeatedly crash the system and sustain the Denial of Service (DoS) condition. This issue affects:
    Juniper Networks Junos OS: All versions, including the following supported releases: 15.1 versions prior
    to 15.1R7-S10; 17.4 versions prior to 17.4R3-S5; 18.3 versions prior to 18.3R3-S5; 18.4 versions prior to
    18.4R3-S9; 19.1 versions prior to 19.1R3-S6; 19.2 versions prior to 19.2R1-S7, 19.2R3-S3; 19.3 versions
    prior to 19.3R2-S6, 19.3R3-S3; 19.4 versions prior to 19.4R3-S6; 20.1 versions prior to 20.1R2-S2,
    20.1R3-S1; 20.2 versions prior to 20.2R3-S2; 20.3 versions prior to 20.3R3; 20.4 versions prior to
    20.4R2-S1, 20.4R3; 21.1 versions prior to 21.1R1-S1, 21.1R2. Juniper Networks Junos OS Evolved: All
    versions prior to 20.4R2-S3-EVO; All versions of 21.1-EVO. (CVE-2021-31359)

  - An improper privilege management vulnerability in the Juniper Networks Junos OS and Junos OS Evolved
    command-line interpreter (CLI) allows a low-privileged user to overwrite local files as root, possibly
    leading to a system integrity issue or Denial of Service (DoS). Depending on the files overwritten,
    exploitation of this vulnerability could lead to a sustained Denial of Service (DoS) condition, requiring
    manual user intervention to recover. This issue affects: Juniper Networks Junos OS: All versions,
    including the following supported releases: 15.1 versions prior to 15.1R7-S10; 17.4 versions prior to
    17.4R3-S5; 18.3 versions prior to 18.3R3-S5; 18.4 versions prior to 18.4R3-S9; 19.1 versions prior to
    19.1R3-S6; 19.2 versions prior to 19.2R1-S7, 19.2R3-S3; 19.3 versions prior to 19.3R2-S6, 19.3R3-S3; 19.4
    versions prior to 19.4R3-S6; 20.1 versions prior to 20.1R2-S2, 20.1R3-S1; 20.2 versions prior to
    20.2R3-S2; 20.3 versions prior to 20.3R3; 20.4 versions prior to 20.4R2-S1, 20.4R3; 21.1 versions prior to
    21.1R1-S1, 21.1R2. Juniper Networks Junos OS Evolved: All versions prior to 20.4R2-S3-EVO; All versions of
    21.1-EVO. (CVE-2021-31360)

Note that Nessus has not tested for this issue but has instead relied only on the application's self- reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11222");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11222");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31359");

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
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');


var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'15.1', 'fixed_ver':'15.1R7-S10'},
  {'min_ver':'17.4', 'fixed_ver':'17.4R3-S5'},
  {'min_ver':'18.3', 'fixed_ver':'18.3R3-S5'},
  {'min_ver':'18.4', 'fixed_ver':'18.4R3-S9'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R3-S6'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R1-S7'},
  {'min_ver':'19.2R2', 'fixed_ver':'19.2R3-S3'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R2-S6'},
  {'min_ver':'19.3R3', 'fixed_ver':'19.3R3-S3'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R3-S6'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R2-S2'},
  {'min_ver':'20.1R3', 'fixed_ver':'20.1R3-S1'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R3-S2'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R3'},
  {'min_ver':'20.4', 'fixed_ver':'20.4R2-S1', 'fixed_display':'20.4R2-S1, 20.4R3'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R1-S1', 'fixed_display':'21.1R1-S1, 21.1R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
