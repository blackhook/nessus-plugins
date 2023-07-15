#TRUSTED 54fda985e9b8c44e670a86c8b06b967e04632ed4e17c0960bc8a4a33f88bfdffe6ba32f287d662ae8d9a4dc3e1959f6dddadc6aa81d64c12448b76eaefd970d6f9cafaca13d16eddf0b5aaa74ed46e7367970699ff8d3e44a3aba72b09decbc2c0b2e2e47268d94c4ad1b4e100dee66bbfcfc6f5199a55b675628598595101c182fa23e31f634b1c07c6ee4c330b52202fb6551277618a48fbf992331ef04346d0587e6c0f66b6bef3e2164b865d402f978f300405381fe0b20684f9ef1a6745d144658ce771e7a3cde2cf6d1587e0a97d5a135b09b77679125b744fee3d0a1c54a6f4f9cfbf7a1410c52ee1f49945493542907f3f62c36f0ae0c108f77f403bd36add0cb4f4c1e766ebabc1089dbff4b0c15ba7a69c65a9dfe524cfb924a560d964cdf3bcb03276e4946d09a6839396e4f70c3f279bfbb7ca443227891284cc2298b8346e0415e8ad8f10ca71a0a5dfdd279c3f5fa772f194ad152cd0df2d51b9496f7ddd3b99fd0014689f79ca340093d206b5d43ddf6291530805151c9d8f35fabcb7c7104e00ea6dacb2af230b7578548d65e4fe622cf2c8a316d37329884b7d203d4a39b03170d31fba210b98b00e4d4aceb077ee386faab821e960e0992413e9247e41e64eebdc6f00871c09485a1a553c57bc60cd4cd6fab807ebc0d032c2290f72c8ce158fbb93e74f3602764ca8b65bb11630a4a0f52bbdacbe3a8b
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(131729);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id("CVE-2018-0195");
  script_bugtraq_id(103557);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuz56428");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180328-rest");

  script_name(english:"Cisco IOS XE Software REST API Authorization Bypass (cisco-sa-20180328-rest)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by an authorization bypass vulnerability in
the REST API due to insufficient authorization checks for requests that are sent to the REST API of the affected
software. An authenticated, remote attacker can exploit this, by sending a malicious request via the REST API, in order
to selectively bypass authorization checks for the REST API and use the API to perform privileged actions on an affected
device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-rest
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e53dbd21");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuz56428");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCuz56428.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0195");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/06");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Settings/ParanoidReport");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');
include('audit.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

vuln_ranges = [{ 'min_ver' : '16.1', 'fix_ver' : '16.2.2' }];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCuz56428'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
