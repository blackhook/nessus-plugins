#TRUSTED 01d50f03843ea3f1245b4cd9f9b622313155b5880c0b3aabbdeec9765e551680c9dfc9ac58beabad5fd0aac9ae2de78a5d4587b54af4c8e880d150103e1998d0dd17792a0b7ad325443e2ee09dae7f272d86d121e4e97ce428cb8c126c63f9f6ed9b6ca59938807b41a40f26ffebb2bf20038466d79c7a3863090a24a02e909b0e254d2a421d1ecf01952f9dd1ca1b37745caa2bbda1083de4ff6728d96418c773b06772fb4efd6bb38c1ddef9294d62272993ee4932367c22fb8008e27fb3fdb9e6a4751b6b99753965b92fe796551d5e6bd21892e64c73836fd28e694813d05b775ddc99ac39cfd815bf25fb9a5d1c6b7cea4090763d8b87ffa05903446cad55da471c688e027a1345d70b619df9cde9f09f6d409e73525ebcc08f47f7e2c480540d55c70132e4f0cbdf12b85285eaa8776ff698bd16a5655f88b1161279b31eace2deeb1c2735894c8a4d64b642587944b04ed3dff5137169717ee1d2ab3b62fedbbe8c7b13e8b981b61582b25bd767edb1d0ad988fb568cc1c38f4fe547fd179045c7ee078282f173f522979d978acd80776ff85ba6838b735b598ca658f2306939ff0ba0c7d41c9e5d046b9df847715be28e26223176fe537d3abe674e9d87480887c951738690f184b3d5b9139c2e1e70e8507021fbf84b0770a8714922d1d51d4c9d165db6f581f360f888f3e81bdd9912e7bcc3d80536bdc5ee4bb70
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(149788);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/21");

  script_cve_id("CVE-2021-0236");
  script_xref(name:"JSA", value:"JSA11131");

  script_name(english:"Juniper Junos OS DoS (JSA11131)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a denial of service (DoS) vulnerability as
referenced in the JSA11131 advisory. The vulnerability exists in the Routing Protocol Daemon (RPD) service due to an
improper check for unusual or exceptional conditions. An authenticated, remote attacker can exploit this, via BGP, to
create a sustained DoS condition.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11131");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11131");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-0236");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/20");

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
include('junos_kb_cmd_func.inc');

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'18.4R1', 'fixed_ver':'18.4R1-S8'},
  {'min_ver':'18.4R2', 'fixed_ver':'18.4R2-S7'},
  {'min_ver':'18.4R3', 'fixed_ver':'18.4R3-S7'},
  {'min_ver':'19.1',   'fixed_ver':'19.1R2-S2'},
  {'min_ver':'19.1R3', 'fixed_ver':'19.1R3-S4'},
  {'min_ver':'19.2',   'fixed_ver':'19.2R1-S6'},
  {'min_ver':'19.2R2', 'fixed_ver':'19.2R3-S2'},
  {'min_ver':'19.3',   'fixed_ver':'19.3R3-S2'},
  {'min_ver':'19.4',   'fixed_ver':'19.4R2-S4'},
  {'min_ver':'19.4R3',   'fixed_ver':'19.4R3-S1'},
  {'min_ver':'20.1',   'fixed_ver':'20.1R2',    'fixed_display':'20.1R2, 20.1R3'},
  {'min_ver':'20.2',   'fixed_ver':'20.2R2',    'fixed_display':'20.2R2, 20.2R3'},
  {'min_ver':'20.3',   'fixed_ver':'20.3R1-S1', 'fixed_display':'20.3R1-S1, 20.3R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var buf = junos_command_kb_item(cmd:'show configuration | display set');
var override = TRUE;
if (buf)
{
  override = FALSE;
  if (!junos_check_config(buf:buf, pattern:"^set protocols bgp group .* family inet6-vpn flow"))
    audit(AUDIT_OS_CONF_NOT_VULN, 'Junos OS');
}
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
