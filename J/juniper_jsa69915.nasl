#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166318);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/21");

  script_cve_id("CVE-2022-22192");
  script_xref(name:"JSA", value:"JSA69915");
  script_xref(name:"IAVA", value:"2022-A-0421");

  script_name(english:"Juniper Junos OS DoS (JSA69915)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a DoS vulnerability as referenced in the JSA69915
advisory. An Improper Validation of Syntactic Correctness of Input vulnerability in the kernel of Juniper Networks
Junos OS Evolved on PTX series allows a network-based, unauthenticated attacker to cause a Denial of Service (DoS).

This issue only affects PTX10004, PTX10008, PTX10016. No other PTX Series devices or other platforms are affected.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://juniper.lightning.force.com/articles/Knowledge/Overview-of-the-Juniper-Networks-SIRT-Quarterly-Security-Bulletin-Publication-Process
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?00a9cacd");
  # https://juniper.lightning.force.com/articles/Knowledge/In-which-releases-are-vulnerabilities-fixed
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?812ee185");
  # https://juniper.lightning.force.com/articles/Knowledge/Common-Vulnerability-Scoring-System-CVSS-and-Juniper-s-Security-Advisories
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d0ab70e2");
  # https://supportportal.juniper.net/s/article/2022-10-Security-Bulletin-Junos-OS-Evolved-PTX-Series-An-attacker-can-cause-a-kernel-panic-by-sending-a-malformed-TCP-packet-to-the-device-CVE-2022-22192
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e14a5283");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA69915");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22192");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/model", "Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');

var model = get_kb_item_or_exit('Host/Juniper/model');
var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

if (model !~ '^PTX100(04|08|16)$' || ver !~ "EVO$")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}
var vuln_ranges = [
  {'min_ver':'20.4', 'fixed_ver':'20.4R3-S4-EVO'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R3-EVO'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R3-EVO'},
  {'min_ver':'22.1', 'fixed_ver':'22.1R2-EVO'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
