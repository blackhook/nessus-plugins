#TRUSTED 413cc677297ae07ecc5f18c65d0b9f82496219f34227ceb5fd9a4ccdb6a643d36a79c3a90042a1cda7acfd797c36177cb97039eec5ad305798c23938352f61ffc435d37ca503251113b88d5c3fc2e8d9c41df483fb347837fd9b5c430c65f3623c0ffb0827fff4bb31b319a63849fb38d9fd4e68a251bc4729da2b77e73ce615c747e733c81241d8a6e42e0af20341c9ae51498b76b13cc33e2606960a0ac1a78b78015ac34377a80e5a81abe698e03c018696139c6dd603124a8e16724d7457f0700a7be9caf0fce367f1297f450c24d7d727a7494e2509573157d3e9963856b063ff8ed0494be80d76ac1c255ca540fedba75e07f9556593a40a951062ebf3a7b1b1304b3282906b6a5241c3233e6e90607ff7eaaec23d7846cc5e78f9d45f78a2e36cf466faa581f58d6f83f626807da58cd58ba91841a93f3cd373f358a0673144438bd9b0a818ab306584530546c98427cfa87b80d59cea1239e6d2224811ff054acb203e9cdf2758f38b37d87373b48c7db9f135d1934d91158703e283dbcdc65c58d0ba270e71dd6de69c3c0a40ef8fd21559b0df2626739f5e2634c2d5e817927d4f517ad16edd26e1a801ed2043f2817058567b4a0aec0593699adc2680c728786f043e484d8dc8d9585a8a9f33bb1483802e6bc04accf616369bfd214c7c9858d6ac8ef63e63b3f5b89a1e7d636983e56b460bcaa4922dde05d23f
#TRUST-RSA-SHA256 5019b755e825a31c74007faa102db810f22907770be75262d6f283e0da9b8d2d4d25674d9f27c25e7acfd78d44e84151b769ac1e4573e2a0020086429102e9a708fd2f8a74cd07d873cc920db58c612b5e185c33bd1f2743d4eb909661cbefc27f9a0823046c2af30e1f95a6f7b97a2c3a9c7026e5e200a8cf9bbc1dc955d7f3790fc917152220763f52ab383629e2f8ff3b3c6901a5c3f07176a4b7a8d62bcc55c438b0fc21ceac6637673eca2e9c6cc5224e24647348aaa9ed8ab39c74de037a599ae15d61a3bfd7013e58bfaceeb8ca6ceb3d5ca0be898a3948d99ff3824dff0ee9b6075eb2f7ac5c57e61b50495a3762b459d8ff0b3f32afd7f47eaa85f0df12175df7f9597044bdab838dc2e2388e57c10df9f74a85b28ffc706119699f9714a283e830ea76356bc6388968b43ae1873a2059fd0e2144434479f6ddd2996019e840a74d505bdbb3ec682a6aaae90229b30aed7e18b541d634bd053b6cdc548c93910642e4ebf962a0c3f8f49e4dfa7bf0c9a999fea436f827f4bf1ab1f6889b1a1f121b550216a38d3702029e50d1a0e8499223025b3ad2c2eda546e54804ed12a2b540cbbcebefb7c3a26dc70cb8a8da1a0c4457c0e45395cd3f36606c712363edeba331f378e8d36195fbc3bc70f7269adfb9925c624ffa375fe91957503d2a0eda938144e7d00ca2872ed370fffb53df5a7b7cd0028650ae2965391e
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136622);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-3312");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq87923");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ftd-infodis-kZxGtUJD");
  script_xref(name:"IAVA", value:"2020-A-0205-S");

  script_name(english:"Cisco Firepower Threat Defense Software Information Disclosure Vulnerability (cisco-sa-ftd-infodis-kZxGtUJD)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"An information disclosure vulnerability exists in Cisco Firepower Threat Defense due to 
insufficient application identification. An unauthenticated, remote attacker can exploit 
this, via specifically crafted traffic, to disclose potentially sensitive information.

see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ftd-infodis-kZxGtUJD
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d3f67674");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq87923");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvq87923");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3312");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl", "cisco_enumerate_firepower.nbin", "cisco_asa_firepower_version.nasl");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver': '6.2.3.15'},
  {'min_ver' : '6.3',  'fix_ver': '6.3.0.5'},
  {'min_ver' : '6.4',  'fix_ver': '6.4.0.6'}
];


reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvq87923',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info, 
  reporting:reporting, 
  vuln_ranges:vuln_ranges
);
