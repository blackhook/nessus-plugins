#TRUSTED 97aa159b84dc044b30c1959493ad4c2ef0b54f85d3e848f88bee9278a7ddad8a181a74909f1d0d76ce1b6789d6c52e06d8149ee1cd6b40ddc4809e01f93833be8020dacc4dd4a97c9adce91fde281659f57715154563c57a7067c369b7d014b2a20c63c0692370955493497ee5cc676ed67b7252f230321c84a756e4f7c6d300d603cb3a8441874a6b4a31d3e38b204cdfedfac2e159a1a6050a4e54e7e7d3a571f78bedb4ce38b25be27cfd186ec5a6d7ecb38bfcfc47307d6e8f2129c339cc2a40a9c1c376b220a07abb868589c8dd6bda1077121b2eaf32b235e36d05a0421ed24805286671b039794ad9999fff2a8ceea76e4cc2f7cf8611fd9b28ec473949aba55b3f4a0cfd91455716d0733c829031593c83528f5d8fbcb05351beaad63c70c1095d11b5d38e04cba7fd3800c21beb5e6382e20a3ccb6d00ac98d43d6ea3f1ff6566edeb9f0e8d98068cf9d6c881c0642ffda92b77e30b7b7ddf74136dca18b0813568c2f591018a81531bae509d7df421eef82e4d4fba2ffd1b76b3a561e1018e2630dac16d14f05b6342fb8c08ca13b94882eb818ba59f9f11fce385b9a3bf4dd7f0524b9d50096716733342ac10b83b1e52ba609ba841786810a1c88816deeb90ef81ff652cb02d46c1babdec6c8b9d00657c051ee857779d7fd75b624224079533e69b4308b4ee87d8a1cc79d022715df20de81e55f351e7a543e7
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(112219);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/30");

  script_cve_id("CVE-2018-11776");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm14030");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180823-apache-struts");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"Cisco Identity Services Engine Struts2 Namespace Vulnerability");
  script_summary(english:"Checks the Cisco Identity Services Engine Software version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Identity Services
Engine Software is affected by a struts2 namespace vulnerability.
Please see the included Cisco BID and the Cisco Security Advisory for
more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180823-apache-struts
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?56a0e547");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm14030");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvm14030.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-11776");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Apache Struts 2 Multiple Tags Result Namespace Handling RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Struts 2 Namespace Redirect OGNL Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");


  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ise_detect.nbin");
  script_require_keys("Host/Cisco/ISE/version");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco Identity Services Engine Software");

vuln_ranges = [
  { 'min_ver' : '2.0.0.0', 'fix_ver' : '2.0.0.306' },
  { 'min_ver' : '2.0.1.0', 'fix_ver' : '2.0.1.130' },
  { 'min_ver' : '2.1.0.0', 'fix_ver' : '2.1.0.474' },
  { 'min_ver' : '2.2.0.0', 'fix_ver' : '2.2.0.470' },
  { 'min_ver' : '2.3.0.0', 'fix_ver' : '2.3.0.298' },
  { 'min_ver' : '2.4.0.0', 'fix_ver' : '2.4.0.357' }
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

# ISE version doesn't change when patches are installed, so even if
# they are on the proper version we have to double check patch level
required_patch = '';
if      (product_info['version'] =~ "^2\.4\.0($|[^0-9])") required_patch = '2';
if      (product_info['version'] =~ "^2\.3\.0($|[^0-9])") required_patch = '4';
if      (product_info['version'] =~ "^2\.2\.0($|[^0-9])") required_patch = '9';
else if (product_info['version'] =~ "^2\.1\.0($|[^0-9])") required_patch = '7';
else if (product_info['version'] =~ "^2\.0\.1($|[^0-9])") required_patch = '7';
else if (product_info['version'] =~ "^2\.0($|[^0-9])")    required_patch = '7';

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , "CSCvm14030",
  'fix'      , 'See advisory'
);

# uses required_patch parameters set by above version ranges
cisco::check_and_report(product_info:product_info, reporting:reporting, workarounds:workarounds, workaround_params:workaround_params, vuln_ranges:vuln_ranges, required_patch:required_patch);
