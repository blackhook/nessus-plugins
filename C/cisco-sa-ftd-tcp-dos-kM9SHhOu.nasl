#TRUSTED 42bb108394f95c4644b83bced816d8f5ba60e5c2909a921b9f44d45095d81d1a29c540bccee6c6b03c519cdca3457bfcbfa15bd2c5ef662a03f9e58770f1e889b3f8b3f43332f011a634217982cb82742ae595484ccbcead0d86e7a903bf67209c104449ebbbf70417f7edc3f3948d8b5ca38368d6b8f7055f9d4850c7ce6271180210b7aee5fae8c645f22a85af949eadb6f2e057bffe839604a9f6f5a7c3f4959fb3dfb6fd11bfc0846e7022a9dd103061dff6357c3ef6e0f6e68a4bad517fd632adc228b50d8390ee8767c5cc3d660d29ca9a25abd160abab492e3ab26fb2ea142d91588569108e04b414264be51141dfcfe23abe3ea5d9de247184828bf6e9b34a1d904a0a7dddc23f839de1272b8c56d7bea555d01196bcc6a4fa6c9ef5846fd3bbe0715e46f946def03d0fe8ca663055737c526e6226152d8aaf16a296014980c81a5a994e3af7db7cd01ed8a193cb47334e417d229b2c6763af4c75fb97e175cfbc41beb4328d9fb12e7b9a61905e5aec3562f9168d60d881841786a373d342757f0c6ed831410078c9b9c9dcaa68da349c317e40044bb55010d3808af74e128415e5a311547740d0dd0e386c6824be2cff8e82c3a07828e8c35a9de8f2a45ad81f3a074694dd0233320aed0cd49900d9eaf1619a73be112a2b4b442d6370c963c023671d8ac1a515c207b1f8c330d95bbb95a3a2cc547f165cf0fbd7
#TRUST-RSA-SHA256 16836636602ca0b33bd6315a04bac3318e45d6384fddd31061173bb139d305716dd15825befd4b6d2f0554449e9f574819b192256445ae0a713828dba7372fe495817d08faa0960cf844f1fb9b804638c763d6e8bfabaac75b76cfcb47301578927a236317f5487b384251d23af4843478301d8ab2955086c95d9c17109647d823e578d7473c75e1d484d8465a54ab598fcee1990cd2197983ec1548e146d222ead269fd2812ab12ef9cf2fcec81485d0e39151e146f0ecaca44b629ab9ec60d22fc78f42fd0d7d85d9efcdd07a5814c7fad22f518a2cf3e64064deadb9133b1bc36c0d070be410ebb2ecb52a68e11844f08ca1dfc3c48521318bca3cfa769c5e81e966228dd4a23a0752b580c80b4c0de67f0b00161eeb34a55e8da94348ad009d6a397d800e6fd5c404b8b6481249c6a19724362d543f46f5a06150722c5f40391ac5bf6f689ac5f1e2ae07fb3719e3812b11a9ccc6b0f77d6bb6f3f67cb73f1bb46ae98a655e081a5ddd005599bc9b72242f91d3da3925a1d4afcda41a21ff4c0a25250a7944276ea4cd9074b7b1c587523934685702b3181716585f793b1bde749102a0b6b90f7e9721513c7755316a6ad8a3f3ff09bd035e86e66ddad9af7f3e054da39625ba71605931b0c27e7547a3883757668f69e5fcf046adf9989c8ab5498f79e3ac28503045429ee432678cca26025aab11df4309a829371fcc6
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161002);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/21");

  script_cve_id("CVE-2022-20746");
  script_xref(name:"IAVA", value:"2022-A-0184-S");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz00032");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ftd-tcp-dos-kM9SHhOu");

  script_name(english:"Cisco Firepower Threat Defense Software TCP Proxy DoS (cisco-sa-ftd-tcp-dos-kM9SHhOu)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the TCP proxy functionality of Cisco Firepower Threat Defense (FTD) Software could allow an 
unauthenticated, remote attacker to trigger a denial of service (DoS) condition. This vulnerability is due to improper 
handling of TCP flows. An attacker could exploit this vulnerability by sending a crafted stream of TCP traffic through 
an affected device. A successful exploit could allow the attacker to cause the device to reload, resulting in a DoS 
condition.

Please see the included Cisco BID and Cisco Security Advisory for more information.
Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ftd-tcp-dos-kM9SHhOu
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?05fc200a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvz00032");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20746");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(476);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}
include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

var vuln_ranges = [ {'min_ver' : '7.0',  'fix_ver' : '7.0.1'} ];

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['tcp_intercept'];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvz00032',
  'cmds'     , make_list('show running-config policy-map | include embryonic'),
  'fix'      , 'See vendor advisory'
);

cisco::check_and_report(
  product_info:product_info, 
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting, 
  vuln_ranges:vuln_ranges
);