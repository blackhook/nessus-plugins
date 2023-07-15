#TRUSTED 178a65d7b62ad9e96e880381f2d1263c3a23c6c5a7141b6a99cadafc7229de610b94b6632d295b4a9dd624a357e8071fb22ba5018ad7c68d4acdce83545902655629c3603a8e2bd865f59a5dfbf87381e1ad94472c44771492b7f715802a028bab930e4feeca109d4cd65c6092202a1e8e37a4db4461b485530e25d5508f0fa5594dc34a260a59922210a4af71e06fe440b4a25c54bdec986004e7b4c4fe27d9af3575ea1502b388861a269a34a822d1a52255b0cdc9a34fb73932927373becab101ec0194aa17b736a92958e93be15dad4409d50daa333ddd175411024260d33a57b78e73071803d8235fc95c98c47b4ea2477468127b5dd8e163ccaa1af6171ed29911df612f8957724d5a5c1606a20c27407d8ee5a059c79eac745fb520efc1a35fb510221880b10be6a8440e2a89cba79302b2e0ec38019bffcba1c8bfbcf6d945afb246413b4f8dd150a8f8b3b5781e5d92144e510a499f54c3385169384ff8ff9ab625bd5606ff3d764d38232da77cb1a9af85e03a07293076a267be2ce7d0376bb4cdaefdafc62bf5f6c74af6298213e5140fe3a4479a984a560185c97633e328ed5374f5344f4fe47137b817166053f01a375b9fe556004cf93d7ab1165f3127f08d9f5114ed6356ada3bb3d0e109b0059ddcec80f005fa96a7464b3d64cb1871a79994dfec2cc2120fb184e796fba20269b648dfe59ee78bf6d03b1
#TRUST-RSA-SHA256 3ca100198d94fbbe830c500297ba4a0e1e04019e982c79374c570391ec06861c71103059de5676c3f9c551e813a56d1aa3a91239cff812c69678cb91563ae7a6e1276bdffb98a0f81e390946bbe01cc6a1ceb2a8bafc12795e08d0665736c4246c6b4e7929674dee44b97b9fdd1b2886275ecbd613a5c31e5b3777d0bb62a0abf7fa77ec11788aa08524f866ecaef49cd7bdbd6dc156aa512aa459e3dfe36d460ee50e547fd060dc52ff64d7a4dbc5019c55627650d0698ea570e594e77aa1310d72486af88ba6a7babdb6352630b063b3851456ce4c7d208bfc758bbf3a0f922fc0a7df6d35ed1f6a5efc8cf8f76282526062cc6bda109b9c4ea35351526bf8c7cf43c9ca966873957954640e828eb37704d4c6afb0fe17aefbdc056828b812518d34568e292c9e8b565df85aadfd0573211b0affc08f1d54f02d5d29be4ec83cc398affe33ef5efdfaaa506d6120a1426a4142caac3afb7ce681dbdc80929ff06d3f7912e4e43e280460ab85c628514096025f4a9ff574b1ea3f98998cbf376710272184e303b44715dec080d42997c2a12b60da26fe915ca17d31a442cf873f323a716247ea2253feb259ad65afafbe59a8aa20f9bb6ec9db99be2569ca395c3f70df877f67326f55e1eb289f30807ec0962c02922c4e6d7869b189b15efb51bcfb99a66352d0152a02e3f65b241bfc46ba6649c622084810c67d51b59139
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136914);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-3187");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr55825");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-path-JE3azWw43");
  script_xref(name:"IAVA", value:"2020-A-0205-S");
  script_xref(name:"CEA-ID", value:"CEA-2020-0042");

  script_name(english:"Cisco Adaptive Security Appliance Software Web Services Path Traversal (cisco-sa-asaftd-path-JE3azWw43)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability exists in the web services interface of Cisco Adaptive Security Appliance (ASA) Software due to a lack
of proper input validation of the HTTP URL. An unauthenticated, remote attacker can exploit this, by sending a crafted
HTTP request containing directory traversal character sequences, in order to view or delete arbitrary files on the
targeted system within the web services file system.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-path-JE3azWw43
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7e0745c0");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr55825");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in the Cisco Security Advisory");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3187");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver': '9.6.4.40'},
  {'min_ver' : '9.7',  'fix_ver': '9.8.4.15'},
  {'min_ver' : '9.9',  'fix_ver': '9.9.2.66'},
  {'min_ver' : '9.10',  'fix_ver': '9.10.1.37'},
  {'min_ver' : '9.11',  'fix_ver': '9.12.3.2'},
  {'min_ver' : '9.13',  'fix_ver': '9.13.1.7'}
];

workarounds = make_list(CISCO_WORKAROUNDS['anyconnect_client_services'], CISCO_WORKAROUNDS['ssl_vpn']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr55825',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);

