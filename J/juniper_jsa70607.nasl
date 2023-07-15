#TRUSTED 877f1b694829b6490c812e18a1d77696edf5480d1dea2748f616938a3413ba3c9ea44ad0f392e1b8e57db2e64e1670b08519163422daf02549b3066bdbfc5091d703fd93c58170a2883b236c6054f893c597ea2e25494db7e1bcd461dd982557e59dc5c30090a11ca296988bb14ddea7b97da88809682b89c86238b37b6c2ec9d540f95eb73457dfbb93c59cd7481357c337c9a5f3465b34426541bbc15c0ecf08b9ddaef3a341b7969239d84365db571199007da7d4c273759012834e9c1a246a1eefc15e974494be6dfcf0c2415db5ed3f7eb3d806f2d04e88d145b247c109a80ad07b0b70a8d5a9e574fb2099ab21d17461f27615ebdd0e6245c3a3ac7ada9d803e336b9f7b72f4583d2b3a7bdbb0d4a2ae5bd77c033366f711a9676175aa1a9efd978caab02bdf298c4f413ff5d8bbe95ef031885234e38b85a4bb96f328ae9c8cb56a369a14ba92da8deeb339b588044383133dd1ef6c59bd783ca3f702f68483ea8a92ac1057f842d63c232917ed63c4c73edd84c6fa8f670c6c1459df9ca73faf8261e637ddace0fb406cd108b0193b89cc81de5a5383542a99acdbdb8910d450c38050e048b900e832e9fe3d9b9cbd17193bec1b3e48fa04c45712f57f83d4e23174117574a5d611636631880a5ba63d6df4ec39baf8617b5b2c56e423d402a62c98ba7b16f601ecde8d47b3e4329c397cd66d74634877170ebf9a11
#TRUST-RSA-SHA256 6628ea7586bb41becf5d608906f5b5c31fec85ac1d5b03d42bd174bd9bd2bf916abfea9b0f32faed83c4ed09ed43d9dfd7c4ab812b3a6c14269c6d6f7e55a7401f8ebf8596c91d20d98bc59958c7d177e92e066a349a78247efb5eb737a535b1ac6e3c158ba21d91c8371ba444d1dcea8ff36393aabe67a45dbc15c36c17830d4cac32ed5e3c11afa90950b120cf4f8a48689e294a042253cc5463544e4e4d7420944908f17c7a6e7ab771384d997f8c97424dad9021b404fe7eed50018537e5d95d58d05d99a00f77af6868e536571bc8c3b99d3a856ef5e911a90d163be5cb1ccbef7319d117e8cf477f0d89cc2ea81a41521e81135703726722b7cb52e4d359e587d360a180dcfaf49f53b943624537ddc260cf8018bcdf3f47bf10fb795bf482e21ac94060b065c17fcc02a01acee4756a0e4acb653cc67bbf677275060914ab1cd67cc80e33c339112618bd88e56430d268df64c270ee06029b09cc1211a179f501adee8780157a4cf1757701a0d66c7fa0397b58c03fad65a1806122e63acec66328296a67c73deaafa37b570b5bdbd7f661f98b17f0a4aebfc7c3ea7f63aaf4051a48acd1c88ac50588617e0f33be3c2159b47794a8339444cef51deb63d52b43949874c2dc2d96e413218bd2167ea3da098b7d78670e483776e92545b9f0bb23295936ef62088ca7035ee1a92e49b406c16287a3a9d2749014d13e3f
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174738);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2023-28981");
  script_xref(name:"JSA", value:"JSA70607");
  script_xref(name:"IAVA", value:"2023-A-0201");

  script_name(english:"Juniper Junos OS Vulnerability (JSA70607)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA70607
advisory.

  - An Improper Input Validation vulnerability in the kernel of Juniper Networks Junos OS and Junos OS Evolved
    allows an unauthenticated, adjacent attacker to cause a Denial of Service (DoS). If the receipt of router 
    advertisements is enabled on an interface and a specifically malformed RA packet is received, memory 
    corruption will happen which leads to an rpd crash. (CVE-2023-28981)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/2023-04-Security-Bulletin-Junos-OS-and-Junos-OS-Evolved-If-malformed-IPv6-router-advertisements-are-received-memory-corruption-will-occur-which-causes-an-rpd-crash-CVE-2023-28981
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5ad5d7c3");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA70607");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-28981");

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
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'20.3', 'fixed_ver':'20.3R3-S5', 'fixed_display':'20.3R3-S5, 20.3R1-EVO'},
  {'min_ver':'20.4', 'fixed_ver':'20.4R3-S3', 'fixed_display':'20.4R3-S3, 20.4R3-S6-EVO'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R3-S4'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R3'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R3', 'fixed_display':'21.3R3, 21.3R3-EVO'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R2', 'fixed_display':'21.4R2, 21.4R2-EVO'},
  {'min_ver':'22.1', 'fixed_ver':'22.1R2', 'fixed_display':'22.1R2, 22.1R2-EVO'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
