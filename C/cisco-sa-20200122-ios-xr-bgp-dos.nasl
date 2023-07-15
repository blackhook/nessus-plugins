#TRUSTED 1d7051d476f4c4d4b0c265fc94bc056645e79fc83d8cbf340aa4f6e4f75330e4da520cb29f3312ce9da11a346b3181310e4f3b31233c41d2f316905e4ff30740b1a3e200450b17df2532fdfb740b785f87eb13144bf4a51fde780d920f003901dd8de229cdb25167de45ba5e8d09415b72d6b52151e7993355893475de31d675abdb5160f83fc73b995ca699c4559feabc82cad402954b76bb850d13aaf592075fa36a4c3a3cd81830a495bb57763cea7df81870335ba1e10c715d2d5cc745cdc0971425459cb74ccd36b48261f6ed9c862b8a6b39d87d586d95ad9555d0f359b29cbe3c381ff5a53bf3ece1665531e501aa53c6f320dada75d48f5061eef982e7c0329b45e9cbe9f597bdabcda665a71fcfc83eab51aec7040a46b026d7e6e551ccd7d185c213af337d9febb065fd441f097927dd85310aef548189ea12fee65e2c5b6771d5b4c845cdb1d101f727383b3baa5680224e0aa480706e2823908a68cffcb972c9510b264808038e76006e4a5a9bb3c8394936a886c8850e66fd65f6869d3245f6ab380fd89272901b239311d14c646cd6b90afb58d79a367acc980a2af4c6b66888c701a52b140541a15e89a58a7288277fb594dac78afef42010dd67812870c037d708e44141d5af78e4998e93ea575ed384f97b1bd0980d7e43425e684f6d579ab36f68fc40db3ec3fff5a8ce5572b791128c6426047eb97a65
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(133408);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/07");

  script_cve_id("CVE-2019-15989");
  script_bugtraq_id(109043);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr69950");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20200122-ios-xr-bgp-dos");
  script_xref(name:"IAVA", value:"2020-A-0041-S");

  script_name(english:"Cisco IOS XR Software Border Gateway Protocol Denial of Service Vulnerability (cisco-sa-20200122-ios-xr-bgp-dos)");
  script_summary(english:"Checks the version of Cisco IOS XR Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR Software is affected by a denial of service vulnerability. 
A remote attacker could exploit this vulnerability by sending specially crafted BGP update messages, which could
cause the BGP process to restart, resulting in a denial of service.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20200122-ios-xr-bgp-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?93dce29c");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr69950");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvr69950");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-15989");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/31");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version", "Settings/ParanoidReport");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:"Cisco IOS XR");

if (report_paranoia < 2) 
  audit(AUDIT_PARANOID);

vuln_ranges = [
  {'min_ver' : '7.0.0',  'fix_ver' : '7.0.2'},
  {'min_ver' : '7.1.0',  'fix_ver' : '7.1.1'},
  {'min_ver' : '7.2.0',  'fix_ver' : '7.2.1'}
];

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['router_bgp'];

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr69950'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);

