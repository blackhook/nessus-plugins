#TRUSTED 7405e94ae76571a6628d8cb0722ec328f0a58ba60bb3cea461778b8193cd85551835cdb4a863ccbbcb5ed8c3f30b5e979a5dd43a3c7c40a9ce799a1d0951abfd9cc006c63095aeb1e6a0f156d1d58918cf9f12c9bcda5e006c23bdea0b29671f13b9acb62b81b197edd4596b58348dc638c71a9845d113dd3ee49b9b9e2ee5209ac6e3fa09d5179fdeba32fe1f22987a69f1867b4448eaba8178c5b2d7d988b0ce7aeb0efc65545c3237284a56e4bdff2e17de9d5b83975f00b982de6d7348fbdf8c95d016683e5c0906eb39ef6abddef00002d678baa30341d5e3779c03a28683d6cb2802edacf43b394ec214192cd696009be2da56aea607b34ccc010a3c7bb2e381a0947bbcb3207109b0f2f73334b302c4f2f0b5f69dc4d5b54377987c832e10d8073b9b130666f3875f29fe9e04792812232b610aad43f7b07a95472d40a4a4eae506031c1c79141cdf60cd19dc406f9d64ef26820be5a24106c6697beecebc13b460e6797237d5ecd087d59cdbb022585ecc8877ea7cd72553e98c04d313c9c3a3e62ad5e3b35a2fa68afb7de5a7849a271657c50e1f361056f4c17819b8cd8219301d3f7d2ede33f42ea47a407852c0325c54fd4696d47c053d6e0316e8f19a638c2bc25c6299e4bbd49fdf4db2ac70476451eb10e5448736b859134dfcdf6da80cf1e18e53ba63642c0907a9c85e132da7da0de9e36110905a47f4dd
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153252);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id("CVE-2021-0281");
  script_xref(name:"JSA", value:"JSA11185");
  script_xref(name:"IAVA", value:"2021-A-0324-S");

  script_name(english:"Juniper Junos OS DoS (JSA11185)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a denial of service vulnerability as referenced
in the JSA11185 advisory.

  - On Juniper Networks Junos OS and Junos OS Evolved devices configured with BGP origin validation using
    Resource Public Key Infrastructure (RPKI) receipt of a specific packet from the RPKI cache server may
    cause routing process daemon (RPD) to crash and restart, creating a Denial of Service (DoS) condition.
    (CVE-2021-0281)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11185");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11185");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-0281");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/14");

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
  {'min_ver':'17.3', 'fixed_ver':'17.3R3-S12'},
  {'min_ver':'17.4', 'fixed_ver':'17.4R3-S5'},
  {'min_ver':'18.1', 'fixed_ver':'18.1R3-S13'},
  {'min_ver':'18.2', 'fixed_ver':'18.2R3-S8'},
  {'min_ver':'18.3', 'fixed_ver':'18.3R3-S5'},
  {'min_ver':'18.4', 'fixed_ver':'18.4R2-S8'},
  {'min_ver':'18.4R3', 'fixed_ver':'18.4R3-S8'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R3-S5'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R3-S2'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R2-S6'},
  {'min_ver':'19.3R3', 'fixed_ver':'19.3R3-S2'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R2-S4'},
  {'min_ver':'19.4R3', 'fixed_ver':'19.4R3-S3'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R3'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R3'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R2'},
  {'min_ver':'20.4', 'fixed_ver':'20.4R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);

var override = TRUE;
var buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  if (!preg(string:buf, pattern:"^set routing-options validation group .* session.*", multiline:TRUE))
    audit(AUDIT_HOST_NOT, 'using a vulnerable configuration');
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
