#TRUSTED 52eda440f4a4670604d203e52e6edcc19c8f3098af1273f8707be7334fee519b9a91a03de4cb37cc17a265fde1f9db9999d865809529b802a92807c7e5d8162fab912dd56343dee7cc085c65d08cfc66f55c87a17001377a29dcb4942cb8675fada45676de0e59b2404fe379325c97f0eee4cd7a4231d4a9a2c4d62d66332bb0ec1c44be40c6cc03f969538a12e0d38c4d1910b16443d8dc5988428dababe5808c33fee320e2afb30239fe4b75094f480792880aafcaa18db5116d57286ad0ee45d9d7f30e26105df81cdd50003c5016888a1ea8f0b9ec7e78a84039576149914eac07e1ceb4e0308be56d892daba7d8ced60b5e9359213096e62275864e479fe547e985199564785ab9979e45d4b541dd05923afbfcd4d599bed55a8e7f93021a6146056f7a3d467789c5ac3c0e1b0fef7246ce60972440868829b87c08307b0ec3161945116e07e456c20ce64690db079398319308069390ed20b7d2324fd0cddaa55a77d473e5e5bd89da523e179270d9bd875f1e28b33d121c1fe4054c5dcf0160dfb3db1085f8d885434b2e7641284b75f2818742688a7c6e87e7332e6eddeb51a2a8b8c76a28e940a09dfb3e7c7c816c8716b1aa488e861d38d76612befab00972f10bbf0a62aba74bb196f21f542d564b353bf6dbeeba2b14f769566196eb3a24fd55713a95f64847dd13631633bcfdde279920f53addbc2267fb23bb
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147766);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/16");

  script_cve_id("CVE-2019-1626");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi69886");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190619-sdwan-privilescal");

  script_name(english:"Cisco SD-WAN Solution Privilege Escalation (cisco-sa-20190619-sdwan-privilescal)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Solution vManage software is affected by a privilege escalation
vulnerability in the web-based UI due to a failure to properly authorize certain user actions in the device
configuration. An authenticated, remote attacker can exploit this to gain elevated privileges on an affected vManage
device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190619-sdwan-privilescal
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ed0412eb");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi69886");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvi69886");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1626");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/19");
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
  { 'min_ver':'0.0', 'fix_ver':'18.4.0' }
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvi69886',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
