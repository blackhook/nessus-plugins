#TRUSTED 846c7ce8d76b1d42ad810bc5c1432a80dccebd5e33026770fd451fc7cfebd27194d0b6c60dae3b6a226a02f3b0400b1f07980d94f82e972d86967e1b4b1d51fafe83c8b9129a15cbd3e0bcc056277dbd1e1937813952b92a616cdce1673e2478fa0dcd67f7eb1e6e437bb0cb4666cf439c5ea991bc97cdebde0558b347ce22f48ee77acc42075301a948476cec1805854d395b2a4cf7b4043a18fbf1c602a86aad1e65000a4af96bb4f54199e14cd521cea971bcb4d437b4fb8c314f8931e95d37044d73a73da3f0a225f572fa57ae3637e909e146bd47491ccdb9ccae86bdd6625255383adc395541ad051357fdb47aefa516397ed09c4e41e0fc74fab9a415a92cc52124c26062e35afb1ceca8fb5941b6498e34ff597b9c9ea8969f14b1e6348fe15a2df782367b66f3338bab2b53e4cbb5e4489176c22e4289f7a6c55f580cd5369819a3724279c26fabb84b364c414271aaf8008d9ff71ce03b6707ecd1f39cf215d728eae7059a9f11be14e76f4ece3402cfb4a860bd2b8eea772a9c50a8fef4ef39cbec8643521ffe307e4d79b25b3bf66f1e5072a8d05c42103389b50423cb3516b36ab53de14765a53686a36c9c25620b5040b4df01c15bd42950a2cb58f6c8c5041d39110d0d1395de7abd857effc79490849151d59803dc7e5455360a9a107f100a1bd7913de0fec06db759c1d9e5d98b2ff6f35fe4a753a68603
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160076);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/26");

  script_cve_id("CVE-2022-22185");
  script_xref(name:"JSA", value:"JSA69493");
  script_xref(name:"IAVA", value:"2022-A-0162");

  script_name(english:"Juniper Junos OS DoS (JSA69493)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA69493
advisory.

  - A vulnerability in Juniper Networks Junos OS on SRX Series, allows a network-based unauthenticated
    attacker to cause a Denial of Service (DoS) by sending a specific fragmented packet to the device,
    resulting in a flowd process crash, which is responsible for packet forwarding. Continued receipt and
    processing of this specific packet will create a sustained DoS condition. This issue only affects SRX
    Series when 'preserve-incoming-fragment-size' feature is enabled. This issue affects Juniper Networks
    Junos OS on SRX Series: 18.3 versions prior to 18.3R3-S6; 18.4 versions prior to 18.4R3-S10; 19.1 versions
    prior to 19.1R3-S7; 19.2 versions prior to 19.2R3-S4; 19.3 versions prior to 19.3R3-S4; 19.4 versions
    prior to 19.4R3-S6; 20.1 versions prior to 20.1R3-S2; 20.2 versions prior to 20.2R3-S3; 20.3 versions
    prior to 20.3R3-S1; 20.4 versions prior to 20.4R3; 21.1 versions prior to 21.1R2-S1, 21.1R3; 21.2 versions
    prior to 21.2R2. This issue does not affect Juniper Networks Junos OS prior to 17.3R1. (CVE-2022-22185)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA69493");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA69493");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22185");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
var model = get_kb_item_or_exit('Host/Juniper/model');

check_model(model:model, flags:SRX_SERIES, exit_on_fail:TRUE);

var vuln_ranges = [
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
  {'min_ver':'21.1', 'fixed_ver':'21.1R2-S1', 'fixed_display':'21.1R2-S1, 21.1R3'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);

var override = TRUE;
var buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  if (!junos_check_config(buf:buf, pattern:"^set security flow preserve-incoming-fragment-size"))
    audit(AUDIT_OS_CONF_NOT_VULN, 'Junos OS');
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
