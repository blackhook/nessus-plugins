#TRUSTED 62ac07c543cbba715d26d821566fe0376a543cfe2d16f0dbdbf94e69d96c823e69c262506abc03f011bc5f17f20971874522712dce5ee11da8255ad606877d5eeb805594f9dfbd094fde9ac4d3660a12b2b083e30bcddd06fcef1a3713b02b4c66171c00162c66886695d99b9a90c5d3f3d0ad9a3fff7bde2cd504c83d3170d5d2ae3b4b7d8173a3bba6dc5d9f1606a4809fa936ad6da1f690c594e9641b59dafaadb843198b7f55cbc47fdc417f2fd31c56a6ad57fcabaafc758f30bd34cec6529d2e97c503401236c29034f5cfed8e58b53232ef3457b20e0f08b5c8ca6d1265b82b02c95966669c9d55fffc8083ab151725a9cf9704d0687c4fd966af99ec69bb3d6ae44b60e34a81bd95068799dbd1bf9bbeefab247024de8cdb5507785ff22de5237d41afe1849acd0a5e79e1fb4d1a7d373cc876ab54dc2a27d8331fc64866bbd0c747586d397036ae17ae2c4c375573f9db35865e50626c01cabf40463597ea2193cb6772c8dea0194873b16f0d032d642868c734106c10be29907a345dd5092558cbe229190681ff24c21d8562a3e1461beb825bbef1d08f73eb798c4b6dc91becc2b6d04625e1ec1b9b7ff1e65b76dd28410ef9d6e5bf1ed4a21406b9d5ba763e450e2524b886fab06da438c0c675a6894e4996009c8505a87880a43650b544a8b1edabacbb48fd903cb6e167619de13b5f2a5cb202dee805347233
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103509);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2017-3886");
  script_bugtraq_id(97432);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc74291");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170405-ucm");

  script_name(english:"Cisco Unified Communications Manager SQL Injection Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Unified
Communications Manager is affected by one or more vulnerabilities.
Please see the included Cisco BIDs and the Cisco Security Advisory for
more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170405-ucm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?93d710d2");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvc74291");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCvc74291.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3886");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/05");
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
  "11.0.1.10000-10.",
  "11.5.1.10000-6."
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();


reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , "CSCvc74291",
  'sqli'     , TRUE
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
