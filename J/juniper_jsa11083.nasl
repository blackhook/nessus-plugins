#TRUSTED 637983a0205e0c615bd338d9af13335b0644890706e093393439e12eb4d6f222f0748dd16fa4fc6584cadffbcc7bb446f61d0ab4e035c2b5adeb7c7f61f8a96f7370db18b774edc262e014586fa067b1ce032393e8806078e3079fe540d872767066b9b2f8f6190f218b1569e1b243a4a6d5a0759c0d0b1a03c0cfd99374d2c90132e8cde9f6ecf40c58d2cfaae6421c66f9ba959b7b3031aee6f0165d6a14cf4bf1bd3afaf643d0c578b2332cc9605814d6f361bde089333131e28333cf4a3528661ff049c0b7a4402e18e2da226c0075b9baa9ae44157bc015c334f6613fd26acabcf8ca9cf10261f9097a7dd63ed1e7506be15200b4145ee0806324c4970c1d1150e39620d8ffd95e6743581836b0f056feff0b2f18ca8159f124767e2fa6d21b1ebaa0af8cf279629c3e857faa6056211faab9da38eefcf177dc8e5f3b57da4a0880d0c741012113ac6fe54214808bc7b8c2224a5d5d917c477c8def85abfa7cfc3592cb93a90f478312942789833c0c42808ce72264013ccafa1fede14e4a8cbbb9f3661f11a1a550fbac12383de6a13e9c3e9a58cf8a3945908157f44bf75368c782482f14413ebf45c59c7f7c54a396256e6d0055c7bce85593ef660812ffc29c2053ed476b8ee9b1b0072df5e112f6c69a773a95c4961f96cc1defd42c6122f5a1991326c82abc4d31fe1efc9f7e935f2b56dc84f3efce4a7d54d9f1
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(143383);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-1686");
  script_xref(name:"JSA", value:"JSA11083");
  script_xref(name:"IAVA", value:"2020-A-0467-S");

  script_name(english:"Junos OS malformed IPv6 packet DoS (JSA11083)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA11083
advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11083");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11083");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1686");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/01");

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
  { 'min_ver':'18.4',   'fixed_ver':'18.4R2-S4'},
  { 'min_ver':'18.4R3', 'fixed_ver':'18.4R3-S1'},
  { 'min_ver':'19.1',   'fixed_ver':'19.1R2-S1', 'fixed_display':'19.1R2-S1, 19.1R3'},
  { 'min_ver':'19.2',   'fixed_ver':'19.2R1-S5', 'fixed_display':'19.2R1-S5, 19.2R2'},
  { 'min_ver':'19.3',   'fixed_ver':'19.3R2-S4', 'fixed_display':'19.3R2-S4, 19.3R3'},
  { 'min_ver':'19.4',   'fixed_ver':'19.4R1-S3', 'fixed_display':'19.4R1-S3, 19.4R2'},
];

fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);

override = TRUE;
#command found at: https://www.juniper.net/documentation/en_US/junos/topics/topic-map/ipv6-interfaces-neighbor-discovery.html
buf = junos_command_kb_item(cmd:'show interfaces terse');
if (buf)
{
  override = FALSE;
  if (!junos_check_config(buf:buf, pattern:'inet6'))
    audit(AUDIT_OS_CONF_NOT_VULN, 'Junos OS');
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);