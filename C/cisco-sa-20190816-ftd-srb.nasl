#TRUSTED 88100184518d1f69b5d0134e50472e28995f3082c21832994cea70ac09388d8eb0702fed39fba22ec6ab3763a6205aa231a7afb1d366bf98f648454ee3eea203b9a72543f2b7836a82336efcb4b8ab250b5b78135b54b2ce8aca2e4a616fd905461fad99791f2fb91059e72e85b727429b5f20fc1aaaaec03906a7530ac5c08ba5d1f3fdbe5d24a1d2d1c9aa8471c161b600a3e682de39393c7c4e83cac7a54ddd5301d38ad9a9bad1231a296b4d180c9dcd68bd34768dd04de130dfd99e99e3bdcfe0f1bc3b290d39d540c90b7391a5c67e2fa1c42f12c91987d61b143753aec2b48b293db78ac4e89d83718dfe2cc4e128847de0cda30fa69169c499f36f4ad45051ce3a4c132caad7b712e2be168f148a1279943b2b87e4af4001ba28b515e779ce2b4317e2b264fc488157e4c6796053788dbb11c4bbd2cb506ce9f131bd3391c912d3c44c5884bed77cd1300c89cf3121b6a5f5b6d51543f90448fda7263958545cdf56bad717d32778814f860d76c743b2d4c8d15f53afdebb5daf11ccdec077be5b5d5a466c5cf1150f9afddd61dbc53c9f538307d5b770868631129d01940ad3e9ccd685dab57ccec06525473c548605069623f9c2caff52e36b8ef38d6975f1aaa18f2c37eb5e93926f26c5daab231646c956e2bd625fa9e19da4159e7b9ab556ce3af5db631c68f057a6dcf86e67a98c40e2a2fc44e8c13f769039
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142497);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/09");

  script_cve_id("CVE-2019-1978");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq39955");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190816-ftd-srb");

  script_name(english:"Cisco Firepower Threat Defense Software Stream Reassembly Bypass (cisco-sa-20190816-ftd-srb)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a stream reassembly bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"A stream reassembly bypass vulnerability exists in Cisco Firepower Threat Defense (FTD) due to improper reassembly of
traffic streams. An unauthenticated, remote attacker can exploit this, by sending specially crafted streams through an
affected device to bypass filtering and deliver malicious requests to protected systems that would otherwise be blocked.

Please see the included Cisco BID and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190816-ftd-srb
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?944df84a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq39955");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in the Cisco Security Advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1978");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_asa_firepower_version.nasl", "cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

version_list = make_list(
  '2.9.12',
  '2.9.12-opensrc',
  '2.9.12.1',
  '2.9.12.12',
  '2.9.12.13',
  '2.9.12.14',
  '2.9.12.15',
  '2.9.12.2',
  '2.9.12.3',
  '2.9.12.4',
  '2.9.12.5',
  '2.9.12.6',
  '2.9.12.7',
  '2.9.12.8',
  '2.9.12.9',
  '2.9.13',
  '2.9.13.1',
  '2.9.13.2',
  '2.9.13.3',
  '2.9.13.4',
  '2.9.13.5',
  '2.9.13.6',
  '2.9.14.0',
  '2.9.14.2',
  '2.9.14.3',
  '2.9.14.4',
  '2.9.14.5',
  '2.9.15',
  '2.9.16',
  '2.9.16.0',
  'pre3.0'
);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvq39955',
  'fix'      , 'See vendor advisory',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
