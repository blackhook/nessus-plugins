#TRUSTED 8ae2f68ca9eb66f57ac6fda1653318aaa1731f0730c550f44011abdd9647e78dba89b15a9874befc66b59accb8ffd63bd5d4a7f64c15fc150c58f3bd2b24008e975b72e0ee0e22b24ac847a3e44c92ea64850d4846c63e45a47d0585cb978095e7683908bb1c3a4d63b64ac2dd4e904efcf3910171553c8c455e402f4c3715f7449e9c4bd1d242da0528fd5502fa9533c42fd2072477825b254cc441ade260bf3c286b7bfdfaaec365f214fc15289594a12b11539a1c55beb40e37ca5fe627659dadd9141cabccda66c5f6f5952bea26f612aab7989dc571e276790bb457d5f355e38a9c2c5b5846f4ab9bb9ae54a1024f4b143e66b53cb234e526d776cd63870d59c7141b697b7b17a2d2b9bec0b17f4d6bca8539664a92fe75f7279ce4c78f11b93cee746dc3a79cd98e8bea8c00f40865cddd3ec73e67fbb8ab6c84d646045b0ae63b498a7614c711636ed255ee0644d8c7b660beaf8264d3ddf524e23e111d37e5b64d1f8842b79707839345e9937187557b49de0faa1e04e738c24d0ada331b472e83656028f88b76b2b46fba2709f8788d5226b9d7678587bbdb5caa1a6a8ad0bcd95dd3ecfe63bbf46622694a1bafc3be65a5c96c1230cd15f30fc30a2d4a4e748b7fdb9de1ff55a6a589195a2910f2fc69bb51c8d931d7acfae77c2541f6ddedfde2b6ab889250f3f05b272eeaf1635bf9349182f30fd5d3a5597b18
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(108957);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/28");

  script_cve_id("CVE-2016-6380");
  script_bugtraq_id(93201);
  script_xref(name:"CISCO-BUG-ID", value:"CSCup90532");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160928-dns");

  script_name(english:"Cisco IOS XE Software DNS Forwarder Denial of Service Vulnerability (cisco-sa-20160928-dns)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the IOS XE is affected
by one or more vulnerabilities. Please see the included Cisco BIDs
and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160928-dns
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?37daabf8");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCup90532");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCup90532.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-6380");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/10");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

var version_list = make_list(
  '3.1.0S',
  '3.1.1S',
  '3.1.2S',
  '3.1.4S',
  '3.1.4aS',
  '3.1.3aS',
  '3.2.1S',
  '3.2.2S',
  '3.3.0S',
  '3.3.1S',
  '3.3.2S',
  '3.4.0S',
  '3.4.1S',
  '3.4.2S',
  '3.4.3S',
  '3.4.4S',
  '3.4.5S',
  '3.4.6S',
  '3.4.0aS',
  '3.1.1SG',
  '3.1.0SG',
  '3.2.0SG',
  '3.2.1SG',
  '3.2.2SG',
  '3.2.3SG',
  '3.2.4SG',
  '3.2.5SG',
  '3.2.6SG',
  '3.2.7SG',
  '3.2.8SG',
  '3.2.9SG',
  '3.2.10SG',
  '3.5.0S',
  '3.5.1S',
  '3.5.2S',
  '3.6.0S',
  '3.6.1S',
  '3.6.2S',
  '3.7.0S',
  '3.7.1S',
  '3.7.2S',
  '3.7.3S',
  '3.7.4S',
  '3.7.5S',
  '3.7.6S',
  '3.7.7S',
  '3.7.4aS',
  '3.7.2tS',
  '3.2.0XO',
  '3.3.0SG',
  '3.3.2SG',
  '3.3.1SG',
  '3.8.0S',
  '3.8.1S',
  '3.8.2S',
  '3.9.1S',
  '3.9.0S',
  '3.9.2S',
  '3.9.1aS',
  '3.9.0aS',
  '3.2.0SE',
  '3.2.1SE',
  '3.2.2SE',
  '3.2.3SE',
  '3.3.0SE',
  '3.3.1SE',
  '3.3.2SE',
  '3.3.3SE',
  '3.3.4SE',
  '3.3.5SE',
  '3.3.0XO',
  '3.3.1XO',
  '3.3.2XO',
  '3.4.0SG',
  '3.4.2SG',
  '3.4.1SG',
  '3.4.3SG',
  '3.4.4SG',
  '3.4.5SG',
  '3.4.6SG',
  '3.4.7SG',
  '3.5.0E',
  '3.5.1E',
  '3.5.2E',
  '3.5.3E',
  '3.10.0S',
  '3.10.1S',
  '3.10.2S',
  '3.10.3S',
  '3.10.4S',
  '3.10.5S',
  '3.10.6S',
  '3.10.7S',
  '3.10.1xbS',
  '3.11.1S',
  '3.11.2S',
  '3.11.0S',
  '3.11.3S',
  '3.11.4S',
  '3.12.0S',
  '3.12.1S',
  '3.12.2S',
  '3.12.3S',
  '3.12.0aS',
  '3.12.4S',
  '3.13.0S',
  '3.13.1S',
  '3.13.2S',
  '3.13.3S',
  '3.13.4S',
  '3.13.5S',
  '3.13.0aS',
  '3.6.0E',
  '3.6.1E',
  '3.6.2aE',
  '3.6.2E',
  '3.6.4E',
  '3.14.0S',
  '3.14.1S',
  '3.14.2S',
  '3.14.3S',
  '3.15.0S',
  '3.15.1S',
  '3.15.2S',
  '3.15.1cS',
  '3.15.3S',
  '3.15.4S',
  '3.3.0SQ',
  '3.3.1SQ',
  '3.4.0SQ',
  '3.4.1SQ',
  '3.7.0E',
  '3.7.1E',
  '3.7.2E',
  '3.7.3E',
  '3.5.0SQ',
  '3.5.1SQ',
  '3.5.2SQ',
  '3.2.0JA',
  '3.8.0E',
  '3.8.1E',
  '3.8.0EX'
);

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['ip_dns_server'];

var reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCup90532',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info, 
  workarounds:workarounds, 
  workaround_params:workaround_params, 
  reporting:reporting, 
  vuln_versions:version_list
);
