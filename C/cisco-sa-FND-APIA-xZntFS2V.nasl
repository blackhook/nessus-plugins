#TRUSTED 23c2b050d46a151bba40b9f736d6b7f01975b5fb7c17dcf375011085407c5f9ce10682400f3bcdfb6152c7dfc1d157177dc36071f8a1ec9384fd8b6ebbd2bfefbd9dac874e9caa9c3e932a4aeed674c26d53ea73d5e373d9949e573fabfb2c5ae9303cbf6e8389ce0f80db79f039a6b731e40c55536a741799af3ccc678bb35574bdca4c0fed7b8bbe87cb4e5e239d118ee268a22bec4d2492fddeb72d8038f7e9be1642f7cc2397f73f1c6e75b7e65256a6ae4398c42cb41706b3e5345f607444de77d9f75e24787c1bd4b87721ee72dfdd101ef25e18f2944595b9c07c12c19b02070b2d5a7d6d417800527912c1a13c4c50a2d649ed57327d60ad6a2fca0627e626c5b8ba264b320eebad58cc761a3db8f4f2408e99c5e8eec994295a4e49044471da568bae7357c652eb7797d2f9c5fb72933b45b5d112fa9decd8a3ac09e41f91e726b4f070f5941843ae86744c85cdb3b8a8d9b6ac70ad16b2bc9d544054e45d1c6a101940468ed269cd1f72eacdd4bfc7d7428167ff2d0970094d3ce60abd8e96d5274453feb6c70c14cc75e6aa1411cf1dbe97fa4a9e9f04049b7b41aabc04e37f88e8482e857fb218072f24b21a7b0cc15dad4d9fd5aa9db892bba392d790e163009e1c2d7eb6e18f7c4686d711ab38aab8f90be034be89d34f7fbb5a6ca0df9f27d11371f0a4621bca2238cfd8bffd70aaa6530549cd62cdbe015d
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(143231);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/01");

  script_cve_id("CVE-2020-3392");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt45296");
  script_xref(name:"CISCO-SA", value:"cisco-sa-FND-APIA-xZntFS2V");

  script_name(english:"Cisco IoT Field Network Director Missing API Authentication (cisco-sa-FND-APIA-xZntFS2V)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A Rest API vulnerability exists in Cisco IoT Field Network Director (IoT-FND) due to IoT-FND not properly authenticating
REST API calls. An unauthenticated, remote attacker can exploit this, by sending API requests to an affected system, to
view sensitive information on the affected system, including information about the devices that the system manages,
without authentication.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-FND-APIA-xZntFS2V
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bce6e5c0");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt45296");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvt45296");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3392");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(306);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:iot_field_network_director");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("iot_field_network_director_webui_detect.nbin");
  script_require_keys("Cisco/IoT Field Network Director/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'IoT Field Network Director');

vuln_ranges = [
  {'min_ver':'0.0', 'fix_ver':'4.6.1'}
];

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvt45296',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);