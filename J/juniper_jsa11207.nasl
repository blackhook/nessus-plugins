#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151626);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2020-8284", "CVE-2020-8285", "CVE-2020-8286");
  script_xref(name:"JSA", value:"JSA11207");
  script_xref(name:"IAVA", value:"2020-A-0581");
  script_xref(name:"IAVA", value:"2021-A-0202-S");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Juniper Junos OS Multiple Vulnerabilities (JSA11207)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by multiple vulnerabilities as referenced in the
JSA11207 advisory.

  - A malicious server can use the FTP PASV response to trick curl 7.73.0 and earlier into connecting back to
    a given IP address and port, and this way potentially make curl extract information about services that
    are otherwise private and not disclosed, for example doing port scanning and service banner extractions.
    (CVE-2020-8284)

  - curl 7.41.0 through 7.73.0 is vulnerable to an improper check for certificate revocation due to
    insufficient verification of the OCSP response. (CVE-2020-8286)

  - curl 7.21.0 to and including 7.73.0 is vulnerable to uncontrolled recursion due to a stack overflow issue
    in FTP wildcard match parsing. (CVE-2020-8285)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11207");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11207");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8286");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/09");
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
  {'min_ver':'17.3', 'fixed_ver':'17.3R3-S12'},
  {'min_ver':'17.4', 'fixed_ver':'17.4R3-S5'},
  {'min_ver':'18.1', 'fixed_ver':'18.1R3-S13'},
  {'min_ver':'18.3', 'fixed_ver':'18.3R3-S5'},
  {'min_ver':'18.4', 'fixed_ver':'18.4R2-S9'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R3-S5'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R3-S2'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R2-S6'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R1-S4'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R2-S2'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R2-S3'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R2'},
  {'min_ver':'20.4', 'fixed_ver':'20.4R1-S1'}
];

fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
