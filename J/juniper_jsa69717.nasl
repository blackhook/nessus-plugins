#TRUSTED 5e4d16a4326b05caf916c3823a0d2dd0f7bed857c1cd80d08353c50dec53db8d313b1a5820cc6dc216f93343259deb19ce628f3e0f69836179ecbfc46bcc049da0ed0cf271e922340732cdb57d50760a938538082786af8d36b3356d8a67b2b07fdd344da53b6bd59fb7395f8dbbed26f29d776d853091d71e83064aff36bbb0dcd0cf668e5ec6cdd39c43dae6db6c37b3e84193dae5c220796bf542f9a62e26a2f296991fd7439cd3f1758f8d117f2a8160927b1316bc8db38231c4a021685d820eb1eea00d0f31c809689b6f020f62cbd55a4b27ce7c2d351ec31f7fc76345a893c97e376dcb45205b4ad30131d4e2f79a9e41a12e830868027d5ebcb03cf0003ca41c7c8451f8a579ea3a0f1bfb9e2f408b5a575258501ccd847340e2b5379be727ad197f3826dd14ca36348af755877a3cb6e0506fba3a534f31bb9c9c20407472527a54bfbee5535a378dfadc4920c9a1d1e695bdd41ed5c226a79f3453784bb88d8fe1d0d8e0403272232fbac9387b496e2dca97a458535d55909c65d54ab85f5c41c6924dd233188f571e594f93df9f4baa7c4fdc684b3587807d60a218828c276f33889f5b5bae259dec7bf12b96ad6e8c023cc26ec27bef837824ddb6477da027c8ba7b3c3b8a9f5cc5440c8afc98501ecf88c84f028100bc11de368d8bf91fcf79c8a773138d3b7d66c88981c13f2a09406a073da60a8bcdb81ffb
#TRUST-RSA-SHA256 18fc0b1c4f92ee2d7f502ace68c93822d2f85247188187a95806a8c71da5d6d41c3ed3cb34cce60cec15bac40c042fba6337b2730e64ee494350cee1bb398769b4faa5baaee8b8f80cc2a2471e8c6cb52788c8bf8eccd0f18031a7906e62b59c8c67554560cf00b09ae7c263ee1e61205ceefdb6d1cf445099e4b7d70bf791ec46e4527c3218bde7553ece58e3e0958a47f6c18986c184e0b22422712646999e57f313b2fbae9999a555993910e3e8a4fcd3df2430f5fe0444b8cb3d3e2033a04c03a957d6a92329722c4c5d4d0ce6dc8e46a161eb8b3947c7b896f0f491028a5634b1c3da9818e46ac09cf9310ee0680cf36269957ed0d482433371bc953a75eb03d5d0ab2ea9b660cc20817a5807aadd892a9ce6f98f6af30fa192dcea2c3286246aaa0e1a458bde94f48bfb409bb58ce2433c242e8cc812902a7a6d70121392fe73d2c22f8e22260e00c5f471531a2e0c3e7259efd2fe05dd317c6fff93f505828c92e1aa7460c6deb47b0f459d190f8f3afeaae5d6e0380131c9c3fee355a8da3b075718423f42d1e5ed1542c402bac0995bcb158ee5804dd79e4ac0b8271db6a2e5943d956f2f126a919995f9c279878ef0341e2473f1fa43fae9becdad9db053c7c003cdd947e7b486c1fdd3dc6e5fc2fb1f6d8bad58d075a55e6d70e94ac14ee798dff0d4201dd121aa2f706bd0b1f0f1c2c9660a8e2deb2c36970943
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(164339);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2022-22213");
  script_xref(name:"JSA", value:"JSA69717");
  script_xref(name:"IAVA", value:"2022-A-0280");

  script_name(english:"Juniper Junos OS Vulnerability (JSA69717)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA69717
advisory.

  - A vulnerability in Handling of Undefined Values in the routing protocol daemon (RPD) process of Juniper
    Networks Junos OS and Junos OS Evolved may allow an unauthenticated network-based attacker to crash the
    RPD process by sending a specific BGP update while the system is under heavy load, leading to a Denial of
    Service (DoS). Continued receipt and processing of this packet will create a sustained Denial of Service
    (DoS) condition. Malicious exploitation of this issue requires a very specific combination of load,
    timing, and configuration of the vulnerable system which is beyond the direct control of the attacker.
    Internal reproduction has only been possible through artificially created load and specially instrumented
    source code. Systems are only vulnerable to this issue if BGP multipath is enabled. Routers not configured
    for BGP multipath are not vulnerable to this issue. This issue affects: Juniper Networks Junos OS: 21.1
    versions prior to 21.1R3-S1; 21.2 versions prior to 21.2R2-S2, 21.2R3; 21.3 versions prior to 21.3R2,
    21.3R3; 21.4 versions prior to 21.4R1-S1, 21.4R2. Juniper Networks Junos OS Evolved: 21.1 versions prior
    to 21.1R3-S1-EVO; 21.2 version 21.2R1-EVO and later versions; 21.3 versions prior to 21.3R3-EVO; 21.4
    versions prior to 21.4R1-S1-EVO, 21.4R2-EVO. This issue does not affect: Juniper Networks Junos OS
    versions prior to 21.1. Juniper Networks Junos OS Evolved versions prior to 21.1-EVO. (CVE-2022-22213)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/Overview-of-the-Juniper-Networks-SIRT-Quarterly-Security-Bulletin-Publication-Process
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?99086ea4");
  # https://supportportal.juniper.net/s/article/In-which-releases-are-vulnerabilities-fixed
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b616ed59");
  # https://supportportal.juniper.net/s/article/Common-Vulnerability-Scoring-System-CVSS-and-Juniper-s-Security-Advisories
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d4fd08b");
  # https://supportportal.juniper.net/s/article/2022-07-Security-Bulletin-Junos-OS-and-Junos-OS-Evolved-Denial-of-Service-DoS-vulnerability-in-RPD-upon-receipt-of-specific-BGP-update-CVE-2022-22213
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eee78d4c");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA69717");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22213");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/23");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

if (ver =~ 'EVO')
{
  var vuln_ranges = [
    {'min_ver':'21.1', 'fixed_ver':'21.1R3-S1-EVO'},
    {'min_ver':'21.2', 'fixed_ver':'21.2R1-EVO'},
    {'min_ver':'21.3', 'fixed_ver':'21.3R3-EVO'},
    {'min_ver':'21.4', 'fixed_ver':'21.4R1-S1-EVO', 'fixed_display':'21.4R1-S1-EVO, 21.4R2-EVO'}
  ];
}
else
{
  var vuln_ranges = [
    {'min_ver':'21.1', 'fixed_ver':'21.1R3-S1'},
    {'min_ver':'21.2', 'fixed_ver':'21.2R2-S2', 'fixed_display':'21.2R2-S2, 21.2R3'},
    {'min_ver':'21.3', 'fixed_ver':'21.3R2', 'fixed_display':'21.3R2, 21.3R3'},
    {'min_ver':'21.4', 'fixed_ver':'21.4R1-S1', 'fixed_display':'21.4R1-S1, 21.4R2'}
  ];
}

var override = TRUE;
var buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  if (!preg(string:buf, pattern:"^set protocols bgp.*multipath"))
    audit(AUDIT_HOST_NOT, 'using a vulnerable configuration');
}

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
