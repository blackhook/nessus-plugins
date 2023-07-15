#TRUSTED 79cbcaddc3c5d99c9317441484cd7ef83b0b5610f93fe0a624c4fe37ac42cb8fc014d91827ef31adcabf7e1caee7ab5ce6db61a52640987795202e314aa1988a424ee926eba801aac24e5f0bc783cd41f3a48292ab94548327a6c1119cd659525ba2ce57f5f31bc82461ec6390c3c1314041e8329d2021ffec39eebcdcd827515ee743fe2da2fc113935d6e536d3cae001a56cdaa10929f91a57de854fbba124f2680692ec798eb990caba475d1e78df4b84d033d46e6d1a3cb84d79136c28b5c8b0f486e2c272bb6d5c7e40c2a35dc2031b5e0db079e0c4052a48d5b0b4ea8c91e97d80fd860e938d257fa2e399975354ada91d0cd07948d831f9b40811e23cf832aaf105acb3bf87a9574f74f2282f56cb3d7a47635c659dbc58b0dfde5599b6d14bc512d006a651d8ce248c66851f9175576b553ef0c2779ea45f1dd65eb1cb9b8d58f65a0bf967f579611a2a61889eebd4f08d2658f1ce843452d47ba2407ad9cc373cc413fdb3fcc33bf04cd7cabbd293ec621c1e4b0966cfaf76b133968f035160c53f3142ca1e932f1b2ae9bcb246e5f01ab36d2c7c4510d26bb5bfc9ba7fe847747f6ef1fb07a44293eaa9a4a7c6a6e5bab5dd81708c18562c6c7c509bb71f1232b16b3913175682e606d83550b337d108a77f53d9d4292f45ebb5e25a79a2efc632183dfdd9da93ca4d8409b8a39baa4eb328f1ec850290e6a881a4
#TRUST-RSA-SHA256 3052e94da3077f9c26bc6e228bd59e696275ea070ca18143c9dae4b66d7d95d472cedcf88d902693b0021013ca323fde66dda34de5f3c81aaa241030171c88321847728f3bbe64a9503bfe1557d19682998301f513a60c92fc6ebc48a70034f2f37d611bcc98464fe49d9ced52786d4721d679cab935dd2cd04859a6b05a5f13e2080be00a00e631daca410ae267fac904983d6e4ca6bce1efc2fc24295b74a47e35b5875d9e245c2ea0b66cae156a3761e0a134c05867da219f3b145b5780c9579cfa35cc393e03fa4de5924de90c2ba9517ea6069ef1b370e48046e5e75527adf48efe1a7a77d33194c3d890803556fa025de7e222de87f8be60bdd65e5c757e901025332c1852e04612caa63481fff16aca1f705e82264ad3a763c4699df5d734fc73010704919f5d25ac7a88fbc1ebf7b354059808aa8658235c5d5abd6a8cb9465c98a98b32b068ac6574cf14e4897859765f021bbec2ddb71845d917431b349194f8f532194c193eabec7226d34a4315da512e0872c0d41e6b0507e7ba97c79df597452ff69f2a17711e9ada511dd95f152039288c0e80872b3606c633ae469902f1a9655f04ae4616420bbc94355edf74d60c921e153ee7d7fbeb603585392caca0df9b3dbcba03f49ca34bf23e32bb8826b00700f487be236f209a674cce05d4efdc134530e7cdcbf32166956a98682f07906f4e0258accd66ad17a1
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161661);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/14");

  script_cve_id("CVE-2022-20730");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz65181");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ftd-sidns-bypass-3PzA5pO");
  script_xref(name:"IAVA", value:"2022-A-0184-S");

  script_name(english:"Cisco Firepower Threat Defense Software Security Intelligence DNS Feed Bypass (cisco-sa-ftd-sidns-bypass-3PzA5pO)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the Security Intelligence feed feature of Cisco Firepower Threat Defense (FTD) Software could allow
 an unauthenticated, remote attacker to bypass the Security Intelligence DNS feed.

This vulnerability is due to incorrect feed update processing. An attacker could exploit this vulnerability by sending 
traffic through an affected device that should be blocked by the affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported 
version number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ftd-sidns-bypass-3PzA5pO
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3b4fbce5");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74836");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz65181");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvz65181");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20730");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(241);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

var vuln_ranges = [
  {'min_ver': '6.0.0', 'fix_ver': '6.2.3.0'},
  {'min_ver': '6.3.0', 'fix_ver': '6.4.0.15'},
  {'min_ver': '6.5.0', 'fix_ver': '6.6.5.2'},
  {'min_ver': '6.7.0', 'fix_ver': '7.0.2'}
];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCvz65181',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
