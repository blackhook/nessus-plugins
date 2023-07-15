#TRUSTED 56ac3fdee6f0e4744b54f832bed8bbb53a4b4cd733de43a993153bbbb01884a33515e6bfc2330aaa7f7ec8eb66e27230d13d5bb5112215da4afc3750359d4f563786a936945ffa7a3cf56977f9e4a07cb6ae8173e853b54b75a58b2d1265b8d42742015d7c746b172984c7d2f386e4d0e3bb50539f0805deb3cb3cb44bbbe911bb3b199e02c9315692dfae4ed16ab15ad9c07965b1929dd265d9f5bb2ae8d4349ae867024b2de3f36ae2ce5f040f1997eb0ef5049ecd253ebdadcbc45c26eb9fed4deb13cad93a808b33a3f59f8cc42bc08ccd55a33526f13269ef784fc16af175d7a35270aaf195563411a5c843f4398f6ae0fb2793c85ec95968edfe3ab530d0c4bb939eb5786a4c7c0dba5481b9c25f67bc589a71e084dabb227f57a2865329191452e6abd0ce39edc1a57c00df513a934b86b96ff57204ccba8be857dce46ec7651003177a74d508779c4f2f6bf78c1cf1406e4dc0a90eb93a5bcb908ab89ba820f6b4861637361b8059ba146f3e033ad14926a7331b7449d05bb3a0729b3ce56010869a23aa166ec9e509573e85e085e1b715eca55541328e29d1f74ed649167792dd3f8738a76c60d15e234bd01d34047c30b0266ac85db40cb82dbd67c02def896da79d9aeb670719a561d59a5ee955535d6b3bc67ccba29d177fa348002a2d62de13009e9cd5dedb1a2222089bfd37ecd5d5428f31d6d4aa01f2ff56
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(110564);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/06");

  script_cve_id("CVE-2018-0327");
  script_bugtraq_id(104194);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg86743");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180516-ident-se-xss");

  script_name(english:"Cisco Identity Services Engine Cross-Site Scripting Vulnerability");
  script_summary(english:"Checks the Cisco Identity Services Engine Software version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Identity Services
Engine Software is affected by a cross-site scripting vulnerability.
Please see the included Cisco BID and the Cisco Security Advisory for
more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180516-ident-se-xss
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?68262716");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg86743");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvg86743.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0327");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/15");

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
  { 'min_ver' : '2.1.0.474', 'fix_ver' : '2.1.0.475' }
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , "CSCvg86743",
  'fix'      , 'See advisory',
  'xss'      , TRUE
);

cisco::check_and_report(product_info:product_info, reporting:reporting, workarounds:workarounds, workaround_params:workaround_params, vuln_ranges:vuln_ranges);
