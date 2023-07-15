#TRUSTED 2529cea196f6c5ad2f8457b307cf8bfef561f246124295d099ab4b2e4182f36507d2b797d15f05d0fd9cbb4faf2c0b7e46310cc6b3c1922873ca6a0738a61946a233e491d9ed517212a11d3c311ee3fdaeb6977eab8460ce0180863d62b420952d8c9bf47a2bfeddd185d5ede76a5320cea114ae1fb32cc8ac95f858143db9f236438f50bdc43515bb834433f3695da2f60ea2b29bc6406b144aca28b233ab92f5d9e9f87422119b6927d3325783fa76f4649ae26368690a6e4656976fb3ebefa2c3791d2eae11b01c504a08713cb00f0aa3665bba9060bf701c56999b11cbb3b38bfefc9ab420ff243e527815c793117b9e943a416e2bff1ae3e250eba0c4c671f0298b67500a1786dc0b0763bf5f22d584d08a3fea453166321a1dbfd92a0f757a47959949bc28a4e38b1989ac070dac257b0ea9e420c655732158a217073be9e1fce3dbc566c31f21f5dd9e97ecd5c0721983d35c5f764d40b1269cf9eb0b74b25fc54476ef69f8726abedad7bb3c85b84e33170baa4f3f272ea52adefa2f1f6db3c6317e4a72d8948e9af67a06e47148cd85979d2ae7f7eab4d9fc897f6e729e453051f4c92aa009c9ac437789aeec492467d6abb1eb1abc07f016e31202624a274432deb3db1ce64e48087915a106c3fdfeb6ed717223600dca42247d3a71187f7197af2cef3d0e0033b65d56d64db5d79342a59dbfe06a1ed94e4baafd
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153253);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id("CVE-2021-0280");
  script_xref(name:"JSA", value:"JSA11184");
  script_xref(name:"IAVA", value:"2021-A-0324-S");

  script_name(english:"Juniper Junos OS DoS (JSA11184)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a denial of service vulnerability
as referenced in the JSA11184 advisory.

  - Due to an Improper Initialization vulnerability in Juniper Networks Junos OS on PTX platforms and QFX10K
    Series with Paradise (PE) chipset-based line cards, ddos-protection configuration changes made from the
    CLI will not take effect as expected beyond the default DDoS (Distributed Denial of Service) settings in
    the Packet Forwarding Engine (PFE). This may cause BFD sessions to flap when a high rate of specific
    packets are received. Flapping of BFD sessions in turn may impact routing protocols and network stability,
    leading to a Denial of Service (DoS) condition. Continued receipt and processing of this packet will
    create a sustained Denial of Service (DoS) condition. (CVE-2021-0280)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11184");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11184");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-0280");

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
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

var model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ "^(PTX|QFX10)")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'17.4', 'fixed_ver':'17.4R3-S5'},
  {'min_ver':'18.2', 'fixed_ver':'18.2R3-S8'},
  {'min_ver':'18.3', 'fixed_ver':'18.3R3-S5'},
  {'min_ver':'18.4', 'fixed_ver':'18.4R2-S8'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R3-S5'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R3-S2'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R3-S2'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R3-S2'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R3'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R2-S3', 'fixed_display':'20.2R2-S3, 20.2R3'},
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
  if (!preg(string:buf, pattern:"^set system ddos-protection (global|protocols).*", multiline:TRUE))
    audit(AUDIT_HOST_NOT, 'using a vulnerable configuration');
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
