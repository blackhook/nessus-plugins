#TRUSTED 54380591b0a537e348fe9b54213f0076e1249898b2b1e1f76e548a23e789e81f95ab8d7975a850cc2468ce292d7700185d294d527197b479de7ca4901c8e902cbd9abe10c5e724f41f3d6f6d5647b9dd21653051eeeab1a10adb26e7240ead48497a7d8b77a84bff469195cd9e84866bd2b50a0af8603040ad9065a483643b459f050fdf44635e5d8c57bbb9807bf8c1f7b4b20430dbccdbcb9d0e261372f59b93f86962c153e3221d9d99be0bd1b9fd2962a388e2743b64566b684f7f3024daf937134cb4c252f42752f1512e991f183bedf9612ced160d147eb24abcc6e0b57297ba258b593e59ed79453f98e0492b3f9eedce01a4f010d3ca4b5cdf0c48be4d9198fe05bad33aeb445b887d9a87bfd717085fc80e923e02ce75a16c092ce6cadab4430812914402de5543264feaeafa617c842a599c71f7f546be52234445923b8d438db281729cb2aeb8671c0304001b5f95f1ad3a1338de7a6f212ddf9f7d1334951ede899f1a8488ae5c65de31e1d42bd470c1f36fd3eefe81581753e852a824e795dced2545ef87638425d34b9645aa9f1002692863a3b23c79d52b83a1e03acbd675faa1a4e1226607f03c38470a1ef24d61da5c49495b023a31e7981c0e1e084ebfa8a7db8df8db653c281735967e85d37b2c2cedc3aa05ffd2e8ee306cd36378056b3d9281008bd16b68b011f8ab21934ffcbeeeb4c84986d29d5c
#TRUST-RSA-SHA256 2e54efab73f6ed087a17d71402057d227006c974cd2a565b00373508b21efb72d1d60d9fc39ce259b03234399dc553bcbfff7334b0fcfd4055841743e377fe21fce3d974379d69c311085377091e019b741c8531714825326f81f15a252bbc2500c341b8d1e78f7142da30873c18a073c942d19f3701d1dc027854fda6056a5be245c5b7e6aad7dbe612bd04f5fed5b44edc4dbadf971dd967a1601895349e148c129d64bbd41127ece62f8571aacb529bde4bcd31ea82057638768a62b818e06db2cecd1672bfc9ced42dff33fd86ea80945589840b7ff007ab2a3fdd7e7b3a36e3bae3041e9516dea4d302690c2400d38c450125cb169106b7b095c229f6f4e40652cc62ee90f764000705b68e92afb9cc9238b86b641710e667706cab8460e4373d5367d9c3a236c567011b7079024280cdd4329bacf2c54193e9e200eea2717718a445f38ea1dc359995337aa2ec7199d1744db01a77662a08c1d1ee27694a229822ed3ac6b2192d390e37e6e9c7e6d6514031b921144da75044ca029b40f16087e6c3d68dabc1cd96500d29cff3c3783b3d557348f7636c39a82dbae8127c4f145f20e320713213b28beca8119fc9a88ea5ce92f999f9032d48482dbcfb0adfc81864b93b10061e5a437a1f61144bce9f121dcd4cf3ece1a6370ce83e78b53e4307a5bfb42d54057423c9547d177490c1b007e96930d21f88a4d5ba6dcb
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149370);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-3563");
  script_xref(name:"IAVA", value:"2020-A-0488-S");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs56888");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ftd-tcp-dos-GDcZDqAf");

  script_name(english:"Cisco Firepower Threat Defense Software TCP Flood DoS (cisco-sa-ftd-tcp-dos-GDcZDqAf)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the packet processing functionality of Cisco Firepower Threat Defense (FTD) 
Software is affected by TCP flood denial of service vulnerability due to inefficient memory management. An 
unauthenticated, remote attacker can exploit this by sending a large number of TCP packets to a specific port on an 
affected device. A successful exploit could allow the attacker to exhaust system memory, which could cause the device 
to reload unexpectedly. No manual intervention is needed to recover the device after it has reloaded.

Please see the included Cisco BID and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ftd-tcp-dos-GDcZDqAf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4edcfe9b");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs56888");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvs56888");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3563");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(400);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

var vuln_ranges = [
  {'min_ver' : '6.3.0',  'fix_ver' : '6.3.0.6'},
  {'min_ver' : '6.4.0',  'fix_ver' : '6.4.0.10'},
  {'min_ver' : '6.5.0',  'fix_ver' : '6.5.0.5'}
];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvs56888',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
