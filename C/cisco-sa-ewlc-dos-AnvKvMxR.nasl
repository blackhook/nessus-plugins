#TRUSTED 57428519801bb2c2c05c3f8239d53284cff7908a4e0a08171ac223507128fb26afee221a67a7f36d0c35f8d53e2ed6740bb5eeeab6a08991cb805ce29de95985b35e3015fdbe8ddb45a989dd8bf0555fb9e479e5715c2bcb2f2c4b38bc1cb7d6500a671be3b3601ec2756127fc95d9cd41fe8c309f4c7126f844c5b9536a8d348ad6baff984b7210edb3a2d6874cae0019c8f22c73af7f839e28c9692f274bd50f46ce92f618ec444dc5394ed0e3948fc2c2a7744aab4f7ec31419ce8f13d793e65b8807ab9360fa26e0dc4b960b2a25a8b653b77490277e0ac8f4b525663ba1c57071fb093e01890bba6ded937713d8b97abe2a737b476efbabc1abbd9402bff63d25368477b07d9853c947da874371c370f4eed81fa1c3b5381f999d6e2ac76effd72be86d18cc4c3fa161a889f36b9ddf14b989bb67342ad881274cbc7548cb8fe49504aef5471c92c21bda081d2b43155019428459dfc0654c074b5b30b861c7d6d9be105f2cd772d963ddc61b396b2bb3b91268dfed637c1b9dc6e0ebcd7cad1b82e1813e27bf3d513d540f21a49de2933480d41e146ad4eee6a51835f2a588a603700a98b722cf48d139c001e5edf8862b87153a320fcd4ba6de52e0487b0c1ccd1bb2f42818a339ad7fb6a6bc16a9fd0baebf2180dec6f82f59b628e4c7568d6d834433a15d48c3ade5d82b5c49b9232823695edb412e506158763228
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137629);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-3206");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo76937");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ewlc-dos-AnvKvMxR");
  script_xref(name:"IAVA", value:"2020-A-0239-S");

  script_name(english:"Cisco IOS XE Software Denial of Service (cisco-sa-ewlc-dos-AnvKvMxR)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a Denial of Service vulnerability. 
The vulnerability exists because the affected software does not properly validate 802.11w disassociation and
deauthentication PMFs that it receives. An unauthenticated, could exploit this vulnerability by sending a spoofed
802.11w PMF from a valid, authenticated client on a network adjacent to an affected device. A successful exploit could
allow the attacker to terminate a single valid user connection to the affected device.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ewlc-dos-AnvKvMxR
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ef21d388");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo76937");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvo76937");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3206");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/18");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

model = product_info['model'];

if( 'catalyst' >!< tolower(model) || (model !~ '98[0-9][0-9]([^0-9]|$)')) 
  audit(AUDIT_HOST_NOT, "affected");

version_list = make_list(
  '16.10.1',
  '16.11.1s',
  '16.12.1e'
);

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvo76937',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);