#TRUSTED 1b9714df4734334ea557fd7838b9d901327bb40453cf4da36c5b9a8cb3cfdf3a75c3fad02ba513007b04969fe01b181a9a3447ab1b3b2147f6aa932fdd05ab5527ed6e7bb07633800118419af01dab278ef47682e813d5dd4bcc9eba9731a0970a516f21021a3d429c3623db05915578982fdeaf42aaa38c709f77a9d8309cd69bb999ddbf6e28ccd2e799f84f738a01f235ff1b1d34445609886856297822bfcd5e2edc7de240347a1ba69d53a65d1206533bacbd01d41db362712a55bdfcdabb0fd1d830ef2150f8c5e148c849dd585784e66dd413b2eedc13cc7e9e78fdf183f0f609962dc18b66028cc658d69315a7d590cbcadf2f39a45d591bd0dfcdedfa61fe543710107b868848da7db763c68857a9136126916f3a594b53748c1f061f511f4f5e7731a4b257378a0789b07f1c29fa63c0a8ce1dbd54a2f639debed4d79af2133dd0e71214afae97bc183724c6d8d71b084e881edd89298cfdeae5f3dbd1ab239eb6d75aeb031e90b228fdd65a7c44f0956d57386114c3bd0956cfa469fb3bd74058a33e52f486fc92b0b4a7f487ab8061ac9775873abf534a1c7312a58dc6aebf34611a54391c35d59bdfe92a086ca2ade365da82931152fb597552764a83175a25f643ae13646533485d15fc46ed1eae621b03aa014f34ead269daf697d30d75c9db048645e23e81fc4af6be6b88e790d98cc7047e08229549030f
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103512);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2017-6654");
  script_bugtraq_id(98527);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc06608");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170517-ucm");

  script_name(english:"Cisco Unified Communications Manager Cross-Site Scripting Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Unified
Communications Manager is affected by one or more vulnerabilities.
Please see the included Cisco BIDs and the Cisco Security Advisory for
more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170517-ucm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b078838d");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvc06608");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCvc06608.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6654");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/27");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ucm_detect.nbin");
  script_require_keys("Host/Cisco/CUCM/Version", "Host/Cisco/CUCM/Version_Display");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");


product_info = cisco::get_product_info(name:"Cisco Unified Communications Manager");

version_list = make_list(
  "10.5.2.10000-5.",
  "11.0.1.10000-10.",
  "11.5.1.10000-6."
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();


reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , "CSCvc06608",
  'xss'      , TRUE
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
