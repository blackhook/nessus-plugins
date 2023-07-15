#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156672);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id("CVE-2022-22164");
  script_xref(name:"JSA", value:"JSA11272");

  script_name(english:"Juniper Junos OS Vulnerability (JSA11272)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA11272
advisory.

  - An Improper Initialization vulnerability in Juniper Networks Junos OS Evolved may cause a commit operation
    for disabling the telnet service to not take effect as expected, resulting in the telnet service staying
    enabled. When it is not intended to be operating on the device, an administrator can issue the following
    command to verify whether telnet is operating in the background: user@device > show system connections |
    grep :23 tcp 0 0 0.0.0.0:23 0.0.0.0:* LISTEN 20879/xinetd This issue affects: Juniper Networks Junos OS
    Evolved All versions prior to 20.4R2-S2-EVO; 21.1 version 21.1R1-EVO and later versions; 21.2 versions
    prior to 21.2R2-EVO. (CVE-2022-22164)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11272");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11272");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22164");

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
  {'min_ver':'21.1', 'fixed_ver':'21.1R1-EVO'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R2-EVO'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
