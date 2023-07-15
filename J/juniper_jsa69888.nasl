#TRUSTED 74131458d81854ef39b5da7e534db0bd6f0c774ead909a63606c16a405913aa527e34659753149f739e50d5663ca359af62803797b679bf54d20e7b719707ed813e56737f079ef6fa5d86ee21585e29268b7502af07785dd435b0807a065d72baf15f302ad4595b01e73abc384ca08506f18fa638bf7528bb2c59170d27e49bd3f4afd9be7b39164dc07bf54a099bb88689a7060a79c162136725bafe5e7b956dbb642921c126fe5647cf69b452a007a21d6eec95a670eb0be205a99960c52b2fe82c714b222eb811d6f85fb24e0db450103dec95fcccf15897774331d90d73eb021b0762ca55c462ca40c24ea1e33f7a9eaff9c90f650052944a6a9f47d0d06bb67dfca84423aac091853159077b5c1dd4bd3afa076e98d0fb582ca1327b6bf358ec56fdebfd1938800730b9ee82100c7c0a287b2e324d50b3247ef4c7185cab2f02f60d63addc284f982013633038110645c4c4336e52199e9d45414e48a01de5c57d77f5d8ab2bff5170d3c0a7d29367642341a22af03dc776fd0e0a5421d83a2041f2c84e15c1e9c01d94f79bcd36aac3998cd001ff91a47a623b9ac470fbcc86262d2746c7988467fe5a0e8f93bb92f4f72deaf59d6f28d03793c46d215b624db88c4c20a2884565e85cbf436560866bffe9b81e98e287f4eaf5d559004ad0be6d14aaf799625b328f0a9421d8df27acd2bed05a5be03396fab4c189d08
#TRUST-RSA-SHA256 8ce2369b85db67bc72d2fd3cb02c5c267a6e5c6e3e26a58cebb65454f1beffa19f797e3cb7e1fbb482af27a237d309fea2b5bb19be4e37e188e6f1fcae50509e990747a0c48289e351c1325daa5d6276a3ac73624afc9a872db9164b4e0309f1202d1c5c88b55bfd5235ef7f545a3794367fab82ef82b6e6a4439d1f58b18a877e7026616c5db228a777c0e837a404ca2743f5cedfe96f9b376393e980a5c1bba7683aea3ee5c875605bc51080bc79f8e81533905e3afbff037d947e0b75a4c84ad6e249e2a08b90024cd911c2099a181865bb39a621e8600227cd3686b47b3206643c9ebfbcecad1c7b214261cd24bc7610a19cc8cb3c4d1e04371a9e44abf2003ef85ba6fc6a7e77df347800d0fe4317400e776b910955d3b8c2dcfc52fd66b9f81e7228bf8df409ccf98da6010fc1edb8c7e62670c63861465b657bd4f784d7004eb1579f5f00ba21394c173c4bc2ba3b303745b9b06cdd555db417ee39a25858ddd3b0d08bcc239e55845f34904180ac903e24c2c24632cb05f7a9cff32112f40ae24a0cb1510ff846b087312f89e9c02fce2903f40bd56a0af6c31d8b6f7e6b1259b67cc6d74a65e5bce30ca8e95e10313860f48183255adc89ca24c8a08cbaa332bb17eee397f8957870abd3c504eab6556bf88411753ae692ca43e2268fbd7619cd95d8bae71e116f67d9f8f3422c79ce6d3504401dfcde9bef9fd9ff
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166682);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/29");

  script_cve_id("CVE-2021-25220");
  script_xref(name:"JSA", value:"JSA69888");

  script_name(english:"Juniper Junos OS Cache Poisoning (JSA69888)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA69888
advisory.

  - BIND 9.11.0 -> 9.11.36 9.12.0 -> 9.16.26 9.17.0 -> 9.18.0 BIND Supported Preview Editions: 9.11.4-S1 ->
    9.11.36-S1 9.16.8-S1 -> 9.16.26-S1 Versions of BIND 9 earlier than those shown - back to 9.1.0, including
    Supported Preview Editions - are also believed to be affected but have not been tested as they are EOL.
    The cache could become poisoned with incorrect records leading to queries being made to the wrong servers,
    which might also result in false information being returned to clients. (CVE-2021-25220)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/2022-10-Security-Bulletin-Junos-OS-SRX-Series-Cache-poisoning-vulnerability-in-BIND-used-by-DNS-Proxy-CVE-2021-25220
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c6e5f4c7");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA69888");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-25220");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/28");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
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
  {'min_ver':'0',    'fixed_ver':'19.3R3-S7'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R2-S8'},
  {'min_ver':'19.4R3', 'fixed_ver':'19.4R3-S9'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R3-S5'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R3-S5'},
  {'min_ver':'20.4', 'fixed_ver':'20.4R3-S4'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R3-S3'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R3-S2'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R3-S1'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R2-S1', 'fixed_display':'21.4R2-S1, 21.4R3'},
  {'min_ver':'22.1', 'fixed_ver':'22.1R1-S2', 'fixed_display':'22.1R1-S2, 22.1R3'},
  {'min_ver':'22.2', 'fixed_ver':'22.2R1-S1', 'fixed_display':'22.2R1-S1, 22.2R2'}
];

var override = TRUE;
var buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  if (!junos_check_config(buf:buf, pattern:"^set system services dns dns-proxy"))
    audit(AUDIT_OS_CONF_NOT_VULN, 'Junos OS');
}

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
