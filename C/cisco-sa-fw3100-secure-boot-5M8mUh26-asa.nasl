#TRUSTED a3e0e7bddbf42f05916ca3ba99f12c8b4fe2f4bd5a3bfec1a212d761d2ad3e16ab7e7e3dd66e14a96ae9caff311fa403e95d9dc00510bff5b05da7d6772be7f8e6301ceebf3206e2e326fbd42987d2bbe51517ee2870d177c7d23f5a37a1585d2b030fe63c64fdb3d7fe18233d0e10d1dbe680ac798856489bcbb72001559d3cc8131bc3d417aed212cc170efe5b3a49ee670f0f6d30d663e5e9b6e00a51f1e5cf5f70b888a2954481bbc740e0a454bb88413f81351bd6d5dba64fbcb79135473ada90bb3c8e8d7290712a1ed10df18cedcb83e05bf2e79f83d549a3e351dd4623c7314dc91d87aa5f50761e5cabceccdd1f57ee1c1e6a0b05ae15c00f0ec542a8fcc0aa7c0b0f15f8e571a2d2ca14cba3537a9192287bec5ae3918fc376cca94cfbf318261595107bc2af7b0303b4be25528bd2b9d149a4d4e0ee4754c47934d8ec46c08e59ebc2677512ba4b06e208618c110d52ade87917a9b30a4487c2275d62038a0458ce4e483d6766b5f2ccc26f5f0196d1a0fc4137d76e635cff1503d4a284528a77aa9819d0535fc32040d92cb6494ab70a38c46d08647b3abbfe07233b92b3bf4cec1e7f02783b2457c6ab63dd92ced6b5027612192c03e5c370f8acc788eb18fc8137fce9fca06c08572f293bddf7f122030ba9034586e1c5b6f95245d969e41dc99ad34f5dcb4278eb708d786fd29fedf79b41d9631fef09d844
#TRUST-RSA-SHA256 adbad96de913fd6b1c020f0bf3d072310c92f92b02acea060a094c1376ad0691920cd863e34511dbbdc55305c088b71a096711ba6f4d8fd19ac844286351df995e74f6d1023d1b11c63d625a58eff211121f08c9e1021f0ee9315c7f6b1aae11cb7e076ae3801ae22d197847bb2ea0eca1ba6c52a6aa47c2f8829b4407bd57d03a79f67e55606d35139857cacb77ea97c36becf8fd41835d1677b0cbd75c78f76a9cdde1a62292f981fe0c4d281993e008517b7233e9a8c9ba1eb7cb37c818b0ddafe482efb091e4ff9cb7b957ae2cb0ca08e6db274b093092dba54620897d22c4fe96212abac87cbf5907293a4df0d48b72966c65e23d33afa0d77ce6cc26be86ca141cb2a56de37bac6522b285fe6f34585a704dbff5e054fa7017067e0aad5789eaae8f4816a1656a6189920a1e80afd4baa08f16f23b01b59ca20909e0566c78518adf1c9c94fae5110b42c23a334838d41e95eafe5e9bf490eb6900784e6a4fe82a3996c9e4cecb9b2c5e103bedb2214d12975b1bd43e8fbcccbea8fb68d3994a46e5be19734a42d4d79f4e0cc4b5399efd038966436f3d458809dfca5d6dcdb6756aeb853694347888528153ed9a86549b12b6ee0bcfe963ec00bd630850d4f83eda60857e3dfc695c312a083748e284c490bb919439851b6e5c85d5a6f50bba61657bd98b779cb7fb80f80f2e1bd725ec20d258d18852f86dd6653711
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(168051);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2022-20826");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwb08411");
  script_xref(name:"CISCO-SA", value:"cisco-sa-fw3100-secure-boot-5M8mUh26");
  script_xref(name:"IAVA", value:"2022-A-0487-S");

  script_name(english:"Cisco Adaptive Security Appliance (ASA) Secure Firewall 3100 Series Secure Boot Bypass (cisco-sa-fw3100-secure-boot-5M8mUh26)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco ASA Software is affected by a vulnerability in the secure boot
implementation of Cisco Secure Firewalls 3100 Series that are running Cisco Adaptive Security Appliance (ASA)
Software or Cisco Firepower Threat Defense (FTD) . A logic error in the boot process could allow an unauthenticated
attacker with physical access to the device to bypass the secure boot functionality by executing persistent code at
boot time to break the chain of trust.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fw3100-secure-boot-5M8mUh26
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?61519c49");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwb08411");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwb08411");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20826");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(501);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

var vuln_ranges = [
  {'min_ver': '9.17', 'fix_ver': '9.17.1.15'},
  {'min_ver': '9.18', 'fix_ver': '9.18.2'}
];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_HOLE,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwb08411',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
