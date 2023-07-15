#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(169951);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/25");

  script_cve_id("CVE-2023-22417");
  script_xref(name:"JSA", value:"JSA70213");
  script_xref(name:"IAVA", value:"2023-A-0041");

  script_name(english:"Juniper Junos OS Vulnerability (JSA70213)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA70213
advisory.

  - A Missing Release of Memory after Effective Lifetime vulnerability in the Flow Processing Daemon (flowd)
    of Juniper Networks Junos OS allows a network-based, unauthenticated attacker to cause a Denial of Service
    (DoS). (CVE-2023-22417)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/Overview-of-the-Juniper-Networks-SIRT-Quarterly-Security-Bulletin-Publication-Process
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?99086ea4");
  # https://supportportal.juniper.net/s/article/In-which-releases-are-vulnerabilities-fixed
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b616ed59");
  # https://supportportal.juniper.net/s/article/Common-Vulnerability-Scoring-System-CVSS-and-Juniper-s-Security-Advisories
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d4fd08b");
  # https://supportportal.juniper.net/s/article/2023-01-Security-Bulletin-Junos-OS-vSRX-Series-A-memory-leak-might-be-observed-in-IPsec-VPN-scenario-leading-to-an-FPC-crash-CVE-2023-22417
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a391b314");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA70213");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-22417");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/12");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');

var model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ "^vSRX")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'19.4', 'fixed_ver':'19.4R2-S8', 'model':'^vSRX'},
  {'min_ver':'19.4R3', 'fixed_ver':'19.4R3-S10', 'model':'^vSRX'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R3-S6', 'model':'^vSRX'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R3-S5', 'model':'^vSRX'},
  {'min_ver':'20.4', 'fixed_ver':'20.4R3-S5', 'model':'^vSRX'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R3-S4', 'model':'^vSRX'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R3', 'model':'^vSRX'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R3', 'model':'^vSRX'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R2', 'model':'^vSRX'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
