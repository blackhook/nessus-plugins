#TRUSTED 7b02d8df1e44e48af24119a8b5d165f54b6684a821d0fa5d0493614911ef56fe88fb22ea6470fa7f06512519ceb113451d012a35ad74b941f8a76741c15d795677950bb09f52bc1c86366395995418b080f424b70b51fe5078c47f11df927b43c8a875c246402a1f065c874bc7631924a9ed94de539a1d7c9f2dc99c6aff53ad2bcb4cf7e1828fb71077600cb1c2d999717ad42e0a9da2a5649f1d567da3cdf4ec19e58f1ca1e5739fdd08993efbb6c46ab862d28e0818b81ae633c08727792070006e3affb2ff882764556f0a32387ea76b846bbb1184d77a298444d1236e8d6118b190ed913979dcc825126f72f16a322257ee9b26b3f694f46e04dcc2c1d5c773167f9e290cd4070fd488c913c168a9356421ff6f91496dcee27b59155a4102a3d4a7e78744503081da74c36d7dff6474ecdf3fdf5f25e959b4a759dc8600e14c69a90ce95207258483fea2d58057d76dc36c247b92d096a5b5847f6828c62f93ba90286e5ff4060ca54b488ea271d3ea7f97dcf15d8f6f04756f4d1f1b120f0dd0d2865e4c781092d149a63867988221343d3289366588986e8a31ac2d5616b797f4e04cb7145abb5aafcd07cacec8f19c36ce3e1d63eb0ffee17987318fe4075f8698ecb733d4bad3a8ec7b0c38b2957a626071c16957b60815650704a7abe1f8b9d398b3ce26d5dc52ee1bb9c0458be5e2dc812d138c0301761737cd7b
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(110567);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/06");

  script_cve_id("CVE-2018-0339");
  script_bugtraq_id(104424);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf72309");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180606-ise-xss");

  script_name(english:"Cisco Identity Services Engine Cross-Site Scripting Vulnerability");
  script_summary(english:"Checks the Cisco Identity Services Engine Software version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Identity Services
Engine Software is affected by a cross-site scripting vulnerability.
Please see the included Cisco BID and the Cisco Security Advisory for
more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180606-ise-xss
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b6021a6f");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvf72309");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvf72309.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0339");

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
  { 'min_ver' : '2.3.0', 'fix_ver' : '2.4.0.357' }
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , "CSCvf72309",
  'fix'      , 'See advisory',
  'xss'      , TRUE
);

cisco::check_and_report(product_info:product_info, reporting:reporting, workarounds:workarounds, workaround_params:workaround_params, vuln_ranges:vuln_ranges);
