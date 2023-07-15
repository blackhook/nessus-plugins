#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151630);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/14");
  script_xref(name:"JSA", value:"JSA11178");

  script_name(english:"Juniper Junos OS Vulnerability (JSA11178)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA11178
advisory.

  - In Juniper Networks Junos OS there are various cases in the IPv6 socket code where the protocol control
    block's state flags are modified during a syscall, but are not restored if the operation fails. This can
    leave the control block in an inconsistent state. The protocol control block is a structure that maintains
    the Network Layer state for various sockets. There are various state flags that must be properly
    maintained to keep the structure consistent. Due to improper maintenance of the IPv6 protocol control
    block flags through various failure paths, an unprivileged authenticated local user may be able to cause a
    NULL pointer dereference causing the kernel to crash allowing an attacker to cause a Denial of Service
    (DoS) condition. (CVE-2018-6925)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-6925");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11178");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11178");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-6925");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/14");

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


ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

vuln_ranges = [
  {'min_ver':'12.3', 'fixed_ver':'12.3R12-S19'},
  {'min_ver':'15.1', 'fixed_ver':'15.1R7-S10'},
  {'min_ver':'17.3', 'fixed_ver':'17.3R3-S12'},
  {'min_ver':'17.4', 'fixed_ver':'17.4R2-S13'},
  {'min_ver':'18.1', 'fixed_ver':'18.1R3-S13'},
  {'min_ver':'18.2', 'fixed_ver':'18.2R3-S8'},
  {'min_ver':'18.3', 'fixed_ver':'18.3R3-S5'},
  {'min_ver':'18.4', 'fixed_ver':'18.4R3-S8'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R3'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R1-S7'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R2-S6'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R1-S4'}
];

fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_NOTE, port:0, extra:report);
