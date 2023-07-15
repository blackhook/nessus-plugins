#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(169283);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/01");

  script_cve_id("CVE-2022-22184");
  script_xref(name:"JSA", value:"JSA70175");
  script_xref(name:"IAVA", value:"2023-A-0012");

  script_name(english:"Juniper Junos OS Vulnerability (JSA70175)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA70175
advisory.

  - An Improper Input Validation vulnerability in the Routing Protocol Daemon (rpd) of Juniper Networks Junos
    OS and Junos OS Evolved allows an unauthenticated network-based attacker to cause a Denial of Service
    (DoS). If a BGP update message is received over an established BGP session, and that message contains a
    specific, optional transitive attribute, this session will be torn down with an update message error. This
    issue cannot propagate beyond an affected system as the processing error occurs as soon as the update is
    received. This issue is exploitable remotely as the respective attribute will propagate through unaffected
    systems and intermediate AS (if any). Continuous receipt of a BGP update containing this attribute will
    create a sustained Denial of Service (DoS) condition. Since this issue only affects 22.3R1, Juniper
    strongly encourages customers to move to 22.3R1-S1. Juniper SIRT felt that the need to promptly warn
    customers about this issue affecting the 22.3R1 versions of Junos OS and Junos OS Evolved warranted an Out
    of Cycle JSA. This issue affects: Juniper Networks Junos OS version 22.3R1. Juniper Networks Junos OS
    Evolved version 22.3R1-EVO. This issue does not affect: Juniper Networks Junos OS versions prior to
    22.3R1. Juniper Networks Junos OS Evolved versions prior to 22.3R1-EVO. (CVE-2022-22184)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/Overview-of-the-Juniper-Networks-SIRT-Quarterly-Security-Bulletin-Publication-Process
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?99086ea4");
  # https://supportportal.juniper.net/s/article/In-which-releases-are-vulnerabilities-fixed
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b616ed59");
  # https://supportportal.juniper.net/s/article/Common-Vulnerability-Scoring-System-CVSS-and-Juniper-s-Security-Advisories
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d4fd08b");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA70175");
  # https://supportportal.juniper.net/s/article/2022-12-Out-of-Cycle-Security-Bulletin-Junos-OS-and-Junos-OS-Evolved-A-BGP-session-will-flap-upon-receipt-of-a-specific-optional-transitive-attribute-in-version-22-3R1-CVE-2022-22184
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?82eb0715");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA70175");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22184");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/23");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"generated_plugin", value:"former");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

if (ver == '22.3R1')
{
  var vuln_ranges = [{'min_ver':'22.3R1', 'max_ver':'22.3R1', 'fixed_ver':'22.4R1', 'fixed_display':'22.3R1-S1, 22.3R2, 22.4R1 or later.'}];
  var junos_fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
  if (empty_or_null(junos_fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
  var junos_report = get_report(ver:ver, fix:junos_fix);
  security_report_v4(severity:SECURITY_HOLE, port:0, extra:junos_report);
}

if (ver == '22.3R1-EVO')
{
  var evo_vuln_ranges = [{'min_ver':'22.3R1-EVO', 'max_ver':'22.3R1-EVO', 'fixed_ver':'22.4R1-EVO', 'fixed_display':'22.3R1-S1-EVO, 22.3R2-EVO, 22.4R1-EVO or later.'}];
}
var evo_fix = junos_compare_range(target_version:ver, vuln_ranges:evo_vuln_ranges);
if (empty_or_null(evo_fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var evo_report = get_report(ver:ver, fix:evo_fix);
security_report_v4(severity:SECURITY_HOLE, port:0, extra:evo_report);

