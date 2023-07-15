#TRUSTED a58e41c87fa83d3cf1ce37393473db63eb356405b1e89c292af239456fde23bf7bbbfb1867493dc4e6c2025da47df4391a2e8eaaf78426e3a0e8f7156f5d36e62c4455ab94b76e2dede68e7a4fce799a02c1a21ad9a3506a439e23b136f281582fc88b9cd52e9a87f9ea342be5bb78f1d8f80e921aa31669de20c4857086adb8cb94c12f07ac0c5783b509783c58adf1e0628cb2430e6a28166ad8afe4f64361066168daa024506dcf48b86b37034e5a63240d2238db3596c25f47279783350672ba65ac7f595dc4e5d2b4f94a1c9e457d8f00ef964cfb8b02c141ee4ce69181494a5e26f3d8429889a6f3cbbb7792ec2f82549e711e02a3e4a7bca3c38ca0d940f64a4a45929cb88b43d137dd5aa292f2dcf26c0df5c6935688f30a7b4e54cb4a1729ab33ac4034bfacd70ab489d81251e810871886b4de578e616e2b4cc0f89087a5bf03d60833732fcdeb260ae248ee40c598a3f6fbfd08c0e21a34c94ce064e3405d1164beaa1ddf24be05e3aa5f542f7cb4e958fd242f2317847c388c4a52594f1931e97ffa4ebeb9160884aea43996d3bf8944e9f602bec690f9fc3e24b7761ae44acd7a5860b77ff7048e1ad6de810ef94e28da6fa649dceb5f0246efee08bb5752a23da18f7ce6c01f176ef7a74a4d4af53d76c30c57dcc08cb778afd14638a0994e171d3bcbd598479785069c17adf88f893ca26605d2427aa1c687
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154115);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/13");

  script_cve_id("CVE-2021-31383");
  script_xref(name:"JSA", value:"JSA11251");
  script_xref(name:"IAVA", value:"2021-A-0478-S");

  script_name(english:"Juniper Junos OS Vulnerability (JSA11251)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA11251
advisory.

  - In Point to MultiPoint (P2MP) scenarios within established sessions between network or adjacent neighbors
    the improper use of a source to destination copy write operation combined with a Stack-based Buffer
    Overflow on certain specific packets processed by the routing protocol daemon (RPD) of Juniper Networks
    Junos OS and Junos OS Evolved sent by a remote unauthenticated network attacker causes the RPD to crash
    causing a Denial of Service (DoS). Continued receipt and processing of these packets will create a
    sustained Denial of Service (DoS) condition. This issue affects: Juniper Networks Junos OS 19.2 versions
    prior to 19.2R3-S2; 19.3 versions prior to 19.3R2-S6, 19.3R3-S2; 19.4 versions prior to 19.4R1-S4,
    19.4R2-S4, 19.4R3-S3; 20.1 versions prior to 20.1R2-S2, 20.1R3; 20.2 versions prior to 20.2R2-S3, 20.2R3;
    20.3 versions prior to 20.3R2. This issue does not affect Juniper Networks Junos OS versions prior to
    19.2R1. Juniper Networks Junos OS Evolved 20.1 versions prior to 20.1R3-EVO; 20.2 versions prior to
    20.2R3-EVO; 20.3 versions prior to 20.3R2-EVO. (CVE-2021-31383)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11251");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11251");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31383");

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
include('junos_kb_cmd_func.inc');

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'19.2', 'fixed_ver':'19.2R3-S2'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R2-S6'},
  {'min_ver':'19.3R3', 'fixed_ver':'19.3R3-S2'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R1-S4', 'fixed_display':'19.4R1-S4, 19.4R2-S4'},
  {'min_ver':'19.4R2', 'fixed_ver':'19.4R2-S4'},
  {'min_ver':'19.4R3', 'fixed_ver':'19.4R3-S3'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R2-S2', 'fixed_display':'20.1R2-S2, 20.1R3'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R2-S3', 'fixed_display':'20.2R2-S3, 20.2R3'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R2', 'fixed_display':'20.3R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);

var override = TRUE;
var buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  if (!(preg(string:buf, pattern:"^set protocols ldp traffic-statistics", multiline:TRUE)) ||
      !(preg(string:buf, pattern:"^set protocols ldp p2mp", multiline:TRUE)) ||
      !(preg(string:buf, pattern:"^set protocols ldp interface", multiline:TRUE))
      )
    audit(AUDIT_HOST_NOT, 'using a vulnerable configuration');
}
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
