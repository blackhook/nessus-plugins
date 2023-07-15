#TRUSTED 96c88a5784a75c379cba0ad3aec2f524e5d4c6c014dc6afd804254c83c6fe7bebb960733e0a766eddf918d5fa7b66218d750833137e12cd1fa069bf5ceb7e67ab17ccce899f0d578d1c21b9b11473cffd3a0b20ce0ac6e9f3428e84b977ed8a9508e9f33f9161a1f056c34d5ecec0522cb2e9232d53934b39a4227afb6941b908e48546ed66bc9bcb7e3545836473d17eee615203270f175ab1c97c3ed9c35031b75bff65706e214fd4d61cecb275c7a88de48647e96bd3d32d0ee516f24ea07df3b0e1b3033e130314615353ca162117b7f6b51226a07b57caa8873ca709d5c8b6fd4071c6758392f2494864887dfabf8672f0562277a05fb95a177ba4d3590ec13c49f19687193c693d49a8ea7d317152d7e3950eb0b222a96f0b53d4e3eeda8d82729e68d5a4c8807fdaf133e32e6d30cc0c031fa48531765f54f5d3e692bd363bb9eba1a653656d266c131b11d0a72e25974cccf6888dd00c1fd3e9665f2f43927ec67307a41cb6c55b117c0ad8e9183f50a9b257c8444f19e6769c1ed61030ff62180419d5394c68754b310fecb8e83041ebad3eaf8733bc4e9f49434bc41e17d3eca335180b3972a7e9305f5eb00bdd0e02c6383ee0e467746c59f41702f2a21c0eae3bf3354ac50207f1b6d5a91906b1cd514c306f9750d723f331065802f92b508589839d82b9240c0eb47734571db06cab7a2f0f96ecd83c3be1ff9
#TRUST-RSA-SHA256 1d25b8e8ecd1c70ea3fc89c2436d7ecd918c70acaece65d120e8145a56cde00caa8e7207941b62805e94fd59744b23e15e2022247d06a7f9ca94574a59a419eaa3f330ab6fa1e6ad84d6dd45bc55e013d581867941f53f01217a1c9839a569bdfe41a10a985e6451b42ccef28605f879aec0ba2b0b386deed9217aa1f5069a8cdabdc72b5a903dfcc3c32cda2b57432003f07a843fd4742ffc7bd4dbfbf997752279337e6b824aa042a5aefdab8b06ec6d3485f7e9b2158aa2b5e9dadc9ca80868d926b88e00c10224c319c0b1903fd200c65e3f01edf7094dcdd4c1079746a5a34a24cdfe7d33b38be0c54b86e247a517460d85ddc902681365d44bb13f65a4d6eb5298b0d70d5d6c9a55d0a529cac1e08216d1e1b1860f4b7ad46220489da8f5efc8f987a6f70dbab991b32782c6432cba89826852725f064bdba38c0a6792fcccfe9653db567577ed2949cf1ed18f9698594d3a73e9350905bf177f8f1ae4b52aa4a9eca701db0a8e30be80350171cf373f8c1f1b0cce7bf37fd11c99396c7582dc8e05bcd43c8165bef6866ccd66f49302dcb72607901caea26d00e2dace2fe4eeffd54c10780df65e5752c1fbf213085d818576389eb4228bc7ef13f19daeac898585c1b6052c05ef6313d12343345a3ed67c5dac42cad0218f403b585f72b588b922255f91d2a138a1917b9c51f17a32f64a8be4cdb094b394e1d51b08
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174737);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2023-28959");
  script_xref(name:"JSA", value:"JSA70584");
  script_xref(name:"IAVA", value:"2023-A-0201");

  script_name(english:"Juniper Junos OS Vulnerability (JSA70584)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the 
JSA70584 advisory.

  - An Improper Check or Handling of Exceptional Conditions vulnerability in packet processing of Juniper
    Networks Junos OS on QFX10002 allows an unauthenticated, adjacent attacker on the local broadcast domain
    sending a malformed packet to the device, causing all PFEs other than the inbound PFE to wedge and to
    eventually restart, resulting in a Denial of Service (DoS) condition. Continued receipt and processing of
    this packet will create a sustained Denial of Service (DoS) condition. (CVE-2023-28959)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/2023-04-Security-Bulletin-Junos-OS-QFX10002-PFE-wedges-and-restarts-upon-receipt-of-specific-malformed-packets-CVE-2023-28959
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?43522fcf");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA70584");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-28959");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');

var model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ "^QFX10002")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'1.0',  'fixed_ver':'19.1R3-S10', 'model':'^QFX10002'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R3-S11', 'model':'^QFX10002'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R3-S7', 'model':'^QFX10002'},
  {'min_ver':'20.4', 'fixed_ver':'20.4R3-S6', 'model':'^QFX10002'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R3-S4', 'model':'^QFX10002'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R3-S4', 'model':'^QFX10002'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R3-S3', 'model':'^QFX10002'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R3-S2', 'model':'^QFX10002'},
  {'min_ver':'22.1', 'fixed_ver':'22.1R3-S1', 'model':'^QFX10002'},
  {'min_ver':'22.2', 'fixed_ver':'22.2R2-S1', 'model':'^QFX10002', 'fixed_display':'22.2R2-S1, 22.2R3'},
  {'min_ver':'22.3', 'fixed_ver':'22.3R1-S2', 'model':'^QFX10002', 'fixed_display':'22.3R1-S2, 22.3R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
