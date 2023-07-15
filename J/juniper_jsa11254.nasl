#TRUSTED 0b7e7a7e6f68855e4f719761d3c481ae8ca14f1e564112d1954da8d27a96a6269ae8d041914f33937bd7632c5c1f1e3628f31afa7cd7db86ba4119f6634a968762810a691c53faf108fdcfa78e5310a4472c2dc155bd2e9e9d788374abc434266af8fce126f86ec73698bb313ca7b90d73e4e9132db374788ede6e5d3f5f2f3c92a5e9dd558c3284d46f84bc9cb05f957b30b3bbd4b31eb5ba0a13d4616fb8a58cc128ebaf86e54706226a89c5e1c2a770695957208f0dae6b5a11757ab0156f940c6948c5fa4dfbfeb1deadafe2b70dc06ba8a712b530684723405718e8f42c44b4296f070a5ed6e87e1cccffd7a90542f4f62a646987b32528fa5e5ce14811ba3e86d54c920883756e54f61d1bfb28d2b0aaff17c220516d756e2d2d79147532b13e35458600e491024469e50e78f56b287c4a4e55125d6e8b30048a1e44dab5f1466d298671406e51b0a36dbe3da00b41b0c745e9016a53b711fd5f55b0d8ed7dce48c79e720d82104a9918af6432a2c2635c5be8d1e1c0cd8a4a2a1f342ca163ac905587692853feb52e34483812a4bad4487b4560178a7c7e10a50bf1e1f827b23333115ca1f4b675d113271ee46dd3c7addf9d110e479e1e24a8ee848a0f41e6ffa10d44ae4a41ca6551b73a599eee694ce45b596380772cdcd41c580074d5b073d67118887efdadf07c2852f05a6d5d406c47a6b212a6ae676ad72a13
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154107);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/13");

  script_cve_id("CVE-2021-31386");
  script_xref(name:"JSA", value:"JSA11254");
  script_xref(name:"IAVA", value:"2021-A-0478-S");

  script_name(english:"Juniper Junos OS Vulnerability (JSA11254)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA11254
advisory.

  - A Protection Mechanism Failure vulnerability in the J-Web HTTP service of Juniper Networks Junos OS allows
    a remote unauthenticated attacker to perform Person-in-the-Middle (PitM) attacks against the device. This
    issue affects: Juniper Networks Junos OS 12.3 versions prior to 12.3R12-S20; 15.1 versions prior to
    15.1R7-S11; 18.3 versions prior to 18.3R3-S6; 18.4 versions prior to 18.4R3-S10; 19.1 versions prior to
    19.1R3-S7; 19.2 versions prior to 19.2R3-S4; 19.3 versions prior to 19.3R3-S4; 19.4 versions prior to
    19.4R3-S6; 20.1 versions prior to 20.1R3-S2; 20.2 versions prior to 20.2R3-S3; 20.3 versions prior to
    20.3R3-S1; 20.4 versions prior to 20.4R3; 21.1 versions prior to 21.1R3; 21.2 versions prior to 21.2R2.
    (CVE-2021-31386)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11254");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11254");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31386");

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
  {'min_ver':'12.3', 'fixed_ver':'12.3R12-S20'},
  {'min_ver':'15.1', 'fixed_ver':'15.1R7-S11'},
  {'min_ver':'18.3', 'fixed_ver':'18.3R3-S6'},
  {'min_ver':'18.4', 'fixed_ver':'18.4R3-S10'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R3-S7'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R3-S4'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R3-S4'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R3-S6'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R3-S2'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R3-S3'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R3-S1'},
  {'min_ver':'20.4', 'fixed_ver':'20.4R3'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R3'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);

var override = TRUE;
var buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  if (!(preg(string:buf, pattern:"^set system services web-management http", multiline:TRUE)))
    audit(AUDIT_HOST_NOT, 'using a vulnerable configuration');
}
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_NOTE);
