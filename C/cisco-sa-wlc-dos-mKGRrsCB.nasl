#TRUSTED 4342d8e8a8b67a193a1e48e0cdbffee1368ea00b8da5cf39bf475dbc408547387d42ba109b40ce8007aa075d72df2f1271d6853ce8ea3de2bc8f8c200c651378f5939d0a6dedab0e87fbe63aed832e4a112b747e0e9f404b40b590672d1927271adee56aa26bfbce5a79ac331953e139b0fb97f07217791bb3017a0edcefedc1413474d3a44d37126959a033185403c761f378dfd0cd5552bae124395d1b25262ebeb561bf1a2e8eaf5b47d2a87fbb3f3962cf8e0d6b5d7e1950936748d6e34bc274c176faa6d172ed33cbd175ee18631cdbf738c416520c67b565a161021dad69172a7696b6f4f246de3ce63e508953afba76b2ea3afcbde2a00b77f52d1d3041203cad23eb871386291e97f5f144b6e1367a22d2375a1a8c7ec06a3625affe1a1778b4fee71408caf713a96a9058c29a6c76dbe04c88386c5fbd1970d07a9170e1c631c7c36a5408b234f0a3af92e2fc5b85ff938975782a1a72ffc77d90b7bcb9c436a8d0a6cf3adb62d6c697d3ea7d49ae54039e2b93e62d37bae85beb2a35b90d05a7920d33b81df93e7a8459a7056d559b8196cc81e86e2b867b4332f920db1898be3793568708247d151ee326adefaf59a45d3d9a08118d4aebe5424c760fe511f53a2de6c8c58f7ac4f088bb81be78b3b67ea09f58740b9b0ae82a38e51d1ae7d67be932f8e364067f7c3267b2b3ffe96e6b54a62ae7db001ae35491
#TRUST-RSA-SHA256 963e4930dbacda4848a34e042bea403bc6d16d6e5b4c92fec872be87f0c5dbe319293d308394700fe50fa62dcab0b6ce9d88dd001d33dface7ce9cc73ac91fe1a4876ad627832c3d33a3b56ac9a7fb5e7d5019947547a046770812abdf0016a545e41f50049986473ff013f59520b4c2d13dfde36da10c538a58bfa4b5713301da9a30eb936b664395b1dccd9f9ad65d6b26ebeada846abb490d3c8687b3a5eae1ac869e94d85513acfe8b41e9fdc48071d3cfa513e6a7bf739ae1e02aee6b28e3c9be4071c6c9e78c00eb1f4017cd386e4d1208df6376a54df1147f9d9e5f10a733ec4e016e71942c99afc28539c7fcdf7cb29636679609b93f879ac30eb31ca770f61a2fa6aea18c951eadc69b866d78aed16dedb8361c67774382e7b44588c851667cc73529d4503a344ac551caa70409b85c1a032f8e144c2956c67d9518a66aa7df10537aea7807f83615121bc3fa261d61c4e62c6455b3bfbf32152b7f8faa334336e78f540a7dd7b7689d46fddba0306792f0c918f134f8cb5e2ed62827347998eb942e75ea924e1be415afba531ca1cffba16fc44ae92129d9668d41b01b4c43f7a14e176d68b0e0245cc04824b6a05a4606e26798cee08774bb9b75657c1c2a30f8d232f7d611d8fc2c091109a9e2cfe4d462e2e3c538cf339aece8de12bef503e3a7f93dd8986b57a237d92895e58839cd23eb208831cba5f15f33
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165695);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/02");

  script_cve_id("CVE-2022-20769");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa40778");
  script_xref(name:"CISCO-SA", value:"cisco-sa-wlc-dos-mKGRrsCB");

  script_name(english:"Cisco Wireless LAN Controller AireOS Software FIPS Mode DoS (cisco-sa-wlc-dos-mKGRrsCB)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Wireless LAN Controller (WLC) is affected by a denial of service (Dos)
vulnerability. An unauthenticated, network-adjacent attacker can send specially crafted packets to an affected device
causing it to crash.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-wlc-dos-mKGRrsCB
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?097704a1");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa40778");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwa40778");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20769");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:wireless_lan_controller_(wlc)");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wlc_version.nasl");
  script_require_keys("Host/Cisco/WLC/Version", "Host/Cisco/WLC/Port");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Wireless LAN Controller (WLC)');

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = [
  WORKAROUND_CONFIG['wlc_fips']
];


var vuln_ranges = [
  {'min_ver': '0.0', 'fix_ver': '8.10.171.0'}
];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwa40778',
  'cmds'          , make_list('show switchconfig')
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  workarounds:workarounds,
  workaround_params:workaround_params,
  vuln_ranges:vuln_ranges
);
