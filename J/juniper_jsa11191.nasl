#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(151637);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");
  script_xref(name:"JSA", value:"JSA11191");
  script_xref(name:"IAVA", value:"2021-A-0324-S");

  script_name(english:"Juniper Junos OS Vulnerability (JSA11191)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA11191
advisory.

  - When user-defined ARP Policer is configured and applied on one or more Aggregated Ethernet (AE) interface
    units, a Time-of-check Time-of-use (TOCTOU) Race Condition vulnerability between the Device Control Daemon
    (DCD) and firewall process (dfwd) daemons of Juniper Networks Junos OS allows an attacker to bypass the
    user-defined ARP Policer. In this particular case the User ARP policer is replaced with default ARP
    policer. (CVE-2021-0289)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-0289");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11191");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11191");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-0289");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/14");

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


ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

vuln_ranges = [
  {'min_ver':'19.4', 'fixed_ver':'19.4R3-S3'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R3'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R3-S2'},
  {'min_ver':'20.4', 'fixed_ver':'20.4R3'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R2'},
  {'min_ver':'18.4', 'fixed_ver':'18.4R2-S9'}
];

fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
