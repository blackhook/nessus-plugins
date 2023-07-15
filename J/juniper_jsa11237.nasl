#TRUSTED a2aa8685e9acaa530f26e791af861988c163fbc9e2ec55288b9bc20c8c9112210df33d11afadca7e278ff44e187606b8dd128aa129baf1b7040ad26d2eb4a3546d36be9902f2dd7f8b6606d1b347beb3e9067969463b67b370605c60047a0a90c5f016b3cabd7c48b39e283c6fbbfc0168cde5d4dd3cac449d50d6f520553f64b61473f5449addaebce659f02d1cf8bef1dd569e9a46a9c9c7e76553ff8dffdd6b37c959bd42a099c2d92f230d61e0f2c1e282e55752b8517f9e8e4a28b26f11395b3627dfd2ea99999bf7512ab1b90d4654fd2427064196dcbf2a4deba1c24f36934d32310e30c956be816747fcffb05c5da9b954e8af468ed750d8c5b2853291961a444905dbbd9b8c2b54dbf5f985158ca7842d16d10100b6938424f5bed455ced05480d2a6b3c99d831557f75b9149f5fccdc6892a05dad9df772c5b570521c82e41ae4cdf421da6b933a826ca5bd8e610ee137d356f151240540b77ae77a3d9a64bec93f298a11c5de356ba48c77f33104bf339aec312de289126e2b9dd4872c12e112f30f877f3a97f4dd9d1ef2e6dbb921af3bfd29bb762f881161f8312db45d804c6b10f5f6d624058e3639a037b03398d44453302de3e1feb0420f8c4139272eaa07e8e38e1559581750407ba5226f0df1bfed4f3a5e632cfa27af6f7a0c2650a0e0fe3bbfb8e833b7853b139a1f9a01058f633984d4e7258c908ce
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159271);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/26");

  script_cve_id("CVE-2021-31372");
  script_xref(name:"JSA", value:"JSA11237");
  script_xref(name:"IAVA", value:"2021-A-0478-S");

  script_name(english:"Juniper Junos OS Privilege Escalation (JSA11237)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA11237
advisory. An Improper Input Validation vulnerability in J-Web of Juniper Networks Junos OS allows a locally
authenticated J-Web attacker to escalate their privileges to root over the target device. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11237");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11237");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31372");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/29");

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

var vuln_ranges = [
  {'min_ver':'0.0', 'fixed_ver':'18.3R3-S5'},
  {'min_ver':'18.4', 'fixed_ver':'18.4R3-S9'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R3-S6'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R3-S3'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R3-S3'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R3-S5'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R3-S1'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R3-S2'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R3-S1'},
  {'min_ver':'20.4', 'fixed_ver':'20.4R3'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R2', 'fixed_display':'21.1R2, 21.1R3'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R1-S1', 'fixed_display':'21.2R1-S1, 21.2R2'}
];

var override = TRUE;
var buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  if (!junos_check_config(buf:buf, pattern:"^set system services web-management"))
    audit(AUDIT_OS_CONF_NOT_VULN, 'Junos OS');
}

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);