#TRUSTED 229722fa3644eb8e02c231617a09f9dc64160c5a211a74a14cfd3ca571f71f31331047198b368661406f6a9c3ab28b51973534e74f76f71a1e69f81616f007f0181bb7b002a6f05b9d45f2491914648c2be9ffc707b3c95e3adb8ddad2b2b642f333778dba3f361749faf54826dcd7251835ac08fcec1d9b3ecd585f407e005066da9f96a4e4d7ebb804b5477bd2a56e9d256bfbf97ca0e90f6e4eccd1f13d0705118831e758e6ce725ca8d81c983f5d266f2b18909d3c27545c50dd6ad07323370877607eced2b4dc26f639a5182057f6ac5a112e0fa29a044de88fc3af7420fe439394a0ae1f1d4932c1bf27c8dc577962c9f96295b37ffae088ee5cca04ccc754c2c8b84291d6b747f990548d7ad39faaf6fcfde23542b6d6864f530275b1bff8f3518ae632809493fce8c811f49684048e2a2e55101d4658bfff84362e2580a150fd16daa273bfaf5f7556f1d5bd60db3a06640ad1edb4e0088e7599bbce6c816cf7b988d3701afe24f27acdfc85388efade0ee3582b0f74cc0867d34575121b57c5c070a4b80337b9c9ecd2b4bc071bdfb6f374084a501e0b62ad0d524eb0067f2aa6cc9c095add27b2303a92c77ff07ead92979bf5691391fa7dae523d300e1faeaaaaa319f68206394fc6947f2ab412b8f60a91dbd76d632df89f413bb7faed9a7f9a2840513e1cd68c84efc048175eeff54ea366159527d8e1ad3887
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154116);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/13");

  script_cve_id("CVE-2021-31369");
  script_xref(name:"JSA", value:"JSA11231");
  script_xref(name:"IAVA", value:"2021-A-0478-S");

  script_name(english:"Juniper Junos OS Vulnerability (JSA11231)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA11231
advisory.

  - On MX Series platforms with MS-MPC/MS-MIC, an Allocation of Resources Without Limits or Throttling
    vulnerability in Juniper Networks Junos OS allows an unauthenticated network attacker to cause a partial
    Denial of Service (DoS) with a high rate of specific traffic. If a Class of Service (CoS) rule is attached
    to the service-set and a high rate of specific traffic is processed by this service-set, for some of the
    other traffic which has services applied and is being processed by this MS-MPC/MS-MIC drops will be
    observed. Continued receipted of this high rate of specific traffic will create a sustained Denial of
    Service (DoS) condition. This issue affects: Juniper Networks Junos OS on MX Series with MS-MPC/MS-MIC:
    All versions prior to 17.4R3-S5; 18.3 versions prior to 18.3R3-S5; 18.4 versions prior to 18.4R3-S9; 19.1
    versions prior to 19.1R3-S6; 19.2 versions prior to 19.2R1-S7, 19.2R3-S3; 19.3 versions prior to
    19.3R2-S7, 19.3R3-S3; 19.4 versions prior to 19.4R3-S5; 20.1 versions prior to 20.1R2-S2, 20.1R3-S1; 20.2
    versions prior to 20.2R3-S2; 20.3 versions prior to 20.3R3; 20.4 versions prior to 20.4R2-S1, 20.4R3; 21.1
    versions prior to 21.1R1-S1, 21.1R2. (CVE-2021-31369)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11231");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11231");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31369");

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
  {'min_ver':'18.3', 'fixed_ver':'18.3R3-S5'},
  {'min_ver':'18.4', 'fixed_ver':'18.4R3-S9'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R3-S6'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R1-S7'},
  {'min_ver':'19.2R2', 'fixed_ver':'19.2R3-S3'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R2-S7'},
  {'min_ver':'19.3R3', 'fixed_ver':'19.3R3-S3'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R3-S5'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R2-S2'},
  {'min_ver':'20.1R3', 'fixed_ver':'20.1R3-S1'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R3-S2'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R3'},
  {'min_ver':'20.4', 'fixed_ver':'20.4R2-S1', 'fixed_display':'20.4R2-S1, 20.4R3'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R1-S1', 'fixed_display':'21.1R1-S1, 21.1R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);

var override = TRUE;
var buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  if (!(preg(string:buf, pattern:"^set services service-set [^\s]+ cos-rule-sets", multiline:TRUE)))
    audit(AUDIT_HOST_NOT, 'using a vulnerable configuration');
}
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
