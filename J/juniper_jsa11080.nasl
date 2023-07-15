#TRUSTED 20fc024b18fcd6e4f9c61abf1a208cb56e1d57e32b846dab03e2a4f5d0f62b52c1495b6fb040c8043994987691a3589b66d6f980eb41a6a3a75981fe562ffd5e8abc2d08e3e0ebdb0bf0f2ca32849eadc2c9927ac3afd410d89b5ee0c7b3318c13ab1e41a89e0fb8597a15af8b0b209c9b71333268e72f4adaba129ca7cc9cdc37b66c8ae4b24238643ad0342cf30dccbbd1582549073a4d5f2450a1894e34265111a62d81b025ffeeb9b7d38ade783aafcc258007be07066751485ee8b71e40c65089f0ae47ca22a13ba5fc58b68d5f65894615c7c30f1305837274b9b91869d418109358aca9f13ea3c5458fb6d52c30188dbc419cef753d06883880f882189c6d0d0a80ff976c09413ce017a05c3a1f923f9fc56dac11b16cf506e7c595a9cc67fb2e1e64b4f68d03ed114f136332df27b92f1078480f4894246d6fc8d507766502f9077f53d019eb7115a8147bee21fa5c1eb4a718d5dc5311c6288739e619f8978d8a714d301b926d74aa9de2703b57e4d01620694cb91097f950b3682acc841cccdb394eebce4878270cfd7576ef5b05d54cb2352552f8de354c617250b603e89639c4b8ec1f32eb8ed8b70f93addd578122b077fa7965e021b5039f840a4a0229d01ea689f8bd0e9627c922c3e60a551ffdc15e16cff5dc24f98fe8b7246c6aab29a5e6c05f37a450f46593db202672da06e011c8ac652affab8f7279
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141849);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-1683");
  script_xref(name:"JSA", value:"JSA11080");
  script_xref(name:"IAVA", value:"2020-A-0467-S");

  script_name(english:"Juniper Junos SNMP DoS (JSA11080)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to the self reported version of Junos OS on the remote device, the device is vulnerable to a denial of
service vulnerability due to a memory leak. An unauthenticated, remote attacker can exploit this, by sending multiple of
a specific SNMP OID poll, to consume increasing amounts of memory, which will eventually lead to a kernel crash
(vmcore). Prior to the crash, other processes might be impacted, such as failure to establish SSH connection to the
device.

Note that Nessus has not attempted to exploit this issue but has instead relied only on the application's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11080");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11080");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1683");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/23");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

vuln_ranges = [
  { 'min_ver':'17.4R3',       'fixed_ver':'17.4R3-S1'},
  { 'min_ver':'18.1R3-S5',    'fixed_ver':'18.1R3-S10' },
  { 'min_ver':'18.2R3',       'fixed_ver':'18.2R3-S3' },
  { 'min_ver':'18.2X75-D50',  'fixed_ver':'18.2X75-D53',  'fixed_display':'18.2X75-D53 or 18.2X75-D60' },
  { 'min_ver':'18.2X75-D420', 'fixed_ver':'18.2X75-D430' },
  { 'min_ver':'18.3R3',       'fixed_ver':'18.3R3-S2' },
  { 'min_ver':'18.4R1-S4',    'fixed_ver':'18.4R2-S5',    'fixed_display':'18.4R2-S5 or 18.4R3-S1' },
  { 'min_ver':'19.1R2',       'fixed_ver':'19.1R2-S2',    'fixed_display':'19.1R2-S2 or 19.1R3' },
  { 'min_ver':'19.2R1',       'fixed_ver':'19.2R1-S5',    'fixed_display':'19.2R1-S5 or 19.2R2' },
  { 'min_ver':'19.3',         'fixed_ver':'19.3R2-S5',    'fixed_display':'19.3R2-S5 or 19.3R3' },
  { 'min_ver':'19.4',         'fixed_ver':'19.4R1-S3',    'fixed_display':'19.4R1-S3 or 19.4R2' }
];

fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);

override = TRUE;
buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  # Vulnerable if SNMP is enabled
  if (!junos_check_config(buf:buf, pattern:'^set snmp '))
    audit(AUDIT_HOST_NOT, 'using a vulnerable configuration');
}

if (!isnull(fix))
  junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
