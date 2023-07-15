#TRUSTED 5bac50f526b9ed9f27d0faf02bc6dd6cb9cc164168b32a7460cd9420996f500a74cc58dfce4148ee084dc011b358537606c349282eae124a87b8671a61c2ccbda2e4ded1f9fca1479f6479b0960ce6261a8153437f383f931a5d917111a86ce98f6e2a2bf679f8bb257286aea6f89680afffbd39937117e6b7ba40b250837de921274523d25490c95f315f298c5937de4bc81450e71119c67b8c17fb26e43c015adc7af695e5bc0a2b092115e4e581ad6070150ad17aed7dad1d27b1fbebb529cd13606286f2710cd0225d68d77951fa072376b5d29a1f7a2c21a26dddbee98cd7666268a6a6c92bb432451154487cb96b1b3f68cf093c61315091e30216f08ab1a41d442c83602645e7bb259b14bfe8c2bf5a5593b681a63d4f9eca76172b35a1716cdc3acdfa4ff45b99eae899ae982e9ef2c4c560641f8980582d2625fffc6583e60c9c2cd106b13da107e6df8e7d4ca4b5714b916578723117b79d9187d09396b37ed7e79bac4df3cb36efd7f2fa26582b14657989d9b01276983d8ac546339d6687c6d4b26bf6146e19d5250a3e5a7113f01d8e596b9eb192b01ea8d4c1eb3c742d90801f9c7a8077f8dea2a06fad03dadffaf34143ca166d3cf46c1c15fee119ddad83f3372a418d010ae6216681ef66b3a6cf5dc9741ec4f6974b070ae136aa57d9bb1a322bf4b9e3a19a7eb97e913df377d37c514192ab70864c2a74
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147764);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/16");

  script_cve_id("CVE-2019-16012");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr42496");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs49675");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20200318-vmanage-cypher-inject");

  script_name(english:"Cisco SD-WAN Solution vManage SQLi (cisco-sa-20200318-vmanage-cypher-inject)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"The version of Cisco SD-WAN Solution vManage installed on the remote host is affected by a vulnerability as referenced
in the cisco-sa-20200318-vmanage-cypher-inject advisory.

  - A vulnerability in the web UI of Cisco SD-WAN Solution vManage software could allow an authenticated,
    remote attacker to conduct SQL injection attacks on an affected system. The vulnerability exists because
    the web UI improperly validates SQL values. An attacker could exploit this vulnerability by authenticating
    to the application and sending malicious SQL queries to an affected system. A successful exploit could
    allow the attacker to modify values on, or return values from, the underlying database as well as the
    operating system. (CVE-2019-16012)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20200318-vmanage-cypher-inject
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e515123b");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr42496");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs49675");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvr42496, CSCvs49675");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-16012");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(77);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Viptela');

if ('vmanage' >!< tolower(product_info['model']))
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
    {'min_ver': '0.0','fix_ver': '19.2.2.0'}
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'bug_id'   , 'CSCvr42496, CSCvs49675',
  'version'  , product_info['version'],
  'disable_caveat', TRUE,
  'sqli'     , TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting
);
