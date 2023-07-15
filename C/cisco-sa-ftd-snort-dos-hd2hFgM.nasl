#TRUSTED 83d24ad2dd0332d6c25111a1947a6994b94aec8b2c3bd871c42b7164e8486fa5880994a25c098382145eb731700e7a3ed132ffe43b150573182b00dfd85fc8c6b309b0e5c9b99fd2d0b45167399a29cb9afa2efac259a87ff5735422547fddf7439fc6502424cc4776505010d9d595d1577a4b84a4b2b7954e80d0a5216c03ed09c3304706aa28a40a8cbf266e92b8b25832ea3ab2123740d6d370a12afc0a0c4f646dd2bf0d622385a500995b01edbc9fee51f659659e4224c244710ad16ae5ea49fa1d4ef493705a6fdec52fd57a2ed1b26c3dc299747b26b44d11035e34fe99fc1f0191025dd2f1319db71ea3c9fcd7c2f48bcf465700fa351b8d4394f970ee1058f01f378ecce6c8b2920e986922a4ba2fff8ea34ccb3002abb229e62c12314610ca7d3d13726e83af341cacb46e5259acd149efc8724e2899d4c8938f223f2b58c0f5171144adce10eeeda673cec05b05bde982001ed610d0b18c4e3a38bbd26d6e3868cf192e9f28ae00bab6c04e7cc89031413dfa358b677d94a614201a5ceac3da18b3028c8925ae93e3c216e9782169357bfa7bd4e93efe1e385b96214297f8e33a370c1c95e033cfa9c85ad73241df1cfa510c47318d528adf59fe01209ffcaa847c8824f210237d72afad203aff8b2c990be887a275922203d11c807819ddf873c7f543123dc559749a6031bc5c07dd52fc3cf42455422198c28b
#TRUST-RSA-SHA256 ac1cf98a571c911a58498057b15f1b29981f1fd3bb122b8c2ff59e32bdc800da0f1d6852cedafa7fa17c8c13e4fa36e61f456817df7e59f28ff991b965291309b0f4d18a6660fdbfb9c46a501c3c4d7a44ecb18b8896ad6664a0d01d769fbb7e3da876c5dc03fc1b24ef85c6bab0fe3fd0c25e0cdf5df3c91056d37c15bf78d3c333ae7e2b026d493d9329326acb42e7f8b789c06f0246bede4ca2fb51464baf436f34f61caff219bd537f38724ae5042da9cefb0219cf74e8e6edcd8b056f92d7f07c51c6d11002bf245c53ce00b2281bf82c2ecefddd4df89ab3242f627838628595199cdcff1f4f9e92654405134761cbb886ce935856ed86d9f219b878df9200d37a9193715a778e6babc783d357285a05eef1107511154f34901a0dc223f032f854b73ae45fd6d9809639c5715cccefdfe8d912a1d51a36d2b4db8ef74b8ca876917c193d6d2792f587aefc6ef2a4d06f00a996d51631341993260cac5abe6909000e23fa332e4494238c5d5be1ae2f4f2818ee61bd14f239d1a8917e585e2e940330660ae8f5ce57bb90ded3f81ebbe4ae909f0a4581247b0c7d90880e1b370a240a7d7d23d9fb19a1019474655ac035682c1d59b9084e92183e64175bbed8e2e6401d3cead274852386166c1eb58a44ec46284c048c00a942e87e3e009f9fbb5e8ff01ea25ae0fd4b06109519e1881f14601391a418dae57510b26732
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160639);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/21");

  script_cve_id("CVE-2022-20751");
  script_xref(name:"IAVA", value:"2022-A-0184-S");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu41615");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ftd-snort-dos-hd2hFgM");

  script_name(english:"Cisco Firepower Threat Defense Software Snort Out of Memory DoS (cisco-sa-ftd-snort-dos-hd2hFgM)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the Snort detection engine integration for Cisco Firepower Threat Defense (FTD) Software could 
allow an unauthenticated, remote attacker to cause unlimited memory consumption, which could lead to a denial of 
service (DoS) condition on an affected device. This vulnerability is due to insufficient memory management for certain 
Snort events. An attacker could exploit this vulnerability by sending a series of crafted IP packets that would 
generate specific Snort events on an affected device. A sustained attack could cause an out of memory condition on the 
affected device. A successful exploit could allow the attacker to interrupt all traffic flowing through the affected 
device. In some circumstances, the attacker may be able to cause the device to reload, resulting in a DoS condition.

Please see the included Cisco BID and Cisco Security Advisory for more information.
Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ftd-snort-dos-hd2hFgM
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c868e825");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu41615");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20751");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(770);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/06");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense", "Settings/ParanoidReport");

  exit(0);
}
include('cisco_workarounds.inc');
include('ccf.inc');

# adding paranoid check instead of checking for connection logging
if (report_paranoia < 2) audit(AUDIT_PARANOID);

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

# Vulnerable model list Cisco Firepower 1000, 2100 and 4100 Series / firewalls FPR-1000, FPR-2100, FPR-4100
if (product_info['model'] !~ "(1[0-9]{3}|1K|(2|4)1[0-9]{2})" || product_info['model'] !~ "(FPR|Firepower )")
    audit(AUDIT_DEVICE_NOT_VULN, 'The ' + product_info['model'] + ' model');

var vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver' : '6.4.0.15'},
  {'min_ver' : '6.5',  'fix_ver' : '6.6.3'},
  {'min_ver' : '6.7',  'fix_ver' : '7.0'}
];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvu41615',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info, 
  reporting:reporting, 
  vuln_ranges:vuln_ranges
);
