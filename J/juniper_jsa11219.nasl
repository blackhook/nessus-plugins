#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154113);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/26");

  script_cve_id("CVE-2021-31354");
  script_xref(name:"JSA", value:"JSA11219");

  script_name(english:"Juniper Junos OS Vulnerability (JSA11219)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA11219
advisory.

  - An Out Of Bounds (OOB) access vulnerability in the handling of responses by a Juniper Agile License (JAL)
    Client in Juniper Networks Junos OS and Junos OS Evolved, configured in Network Mode (to use Juniper Agile
    License Manager) may allow an attacker to cause a partial Denial of Service (DoS), or lead to remote code
    execution (RCE). The vulnerability exists in the packet parsing logic on the client that processes the
    response from the server using a custom protocol. An attacker with control of a JAL License Manager, or
    with access to the local broadcast domain, may be able to spoof a new JAL License Manager and/or craft a
    response to the Junos OS License Client, leading to exploitation of this vulnerability. This issue only
    affects Junos systems configured in Network Mode. Systems that are configured in Standalone Mode (the
    default mode of operation for all systems) are not vulnerable to this issue. This issue affects: Juniper
    Networks Junos OS: 19.2 versions prior to 19.2R3-S3; 19.3 versions prior to 19.3R3-S3; 20.1 versions prior
    to 20.1R2-S2, 20.1R3-S1; 20.2 versions prior to 20.2R3-S2; 20.3 versions prior to 20.3R3; 20.4 versions
    prior to 20.4R3; 21.1 versions prior to 21.1R2. Juniper Networks Junos OS Evolved: version 20.1R1-EVO and
    later versions, prior to 21.2R2-EVO. This issue does not affect Juniper Networks Junos OS versions prior
    to 19.2R1. (CVE-2021-31354)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11219");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11219");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31354");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/13");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');


var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'19.2', 'fixed_ver':'19.2R3-S3'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R3-S3'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R2-S2'},
  {'min_ver':'20.1R3', 'fixed_ver':'20.1R3-S1'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R3-S2'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R3'},
  {'min_ver':'20.4', 'fixed_ver':'20.4R3'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
