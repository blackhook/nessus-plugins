#TRUSTED 287d9eee1c82de7ad12f7183533bb4f1b9f2757edfcf3366fcf64cd8102ca3706b0a9725343cecbc8b2219e9c93232216a3be2d7fb2af9811cf4654c2d776c4030f0ecdb990ff56673ebca788ef1dbdf16514e0d7b68deabf4e5b196f52aa8a4498437b2a143b9d6fb585120eef95e39cac7383fbc45635e5103c2980ee836e1ef33bbbadf02a313114f92fdd30d0500a239200795136c2dcab9ae834361a0870922af9b466507e0d7a1197ef7cf3f46279d9744894c2a6c6f6f654aef4c2d47eff24835b73378d92228314c20e84b1125c2ab2e11070295c249676aafb34299aeb72b957bb87fa966142348caf075795e106de2e56a9df768643fec72bf3ea6616813b0fb7b54c3a5cc0e996a28f3d1dc8dcc830e4fd2a9b3224aa99b00e83cbab5e9ef26a93e683535023d57457aeba6e3af6314974210465d4d5f82bd67ae7435240fa4ee8620ebf4676c1bcfc7c5256c94f5f3410fd5ec83e711e88536829f7d4c69d6b7628dc5819f9f7138998671c49a90b8b253242387ced33d28bb7eee1cbc30a45e19883d4fd6f88d65db52bc88be25536abf9f0507ebc24987f1ff99187d84de64815a57a66eb34430af1b53f04f0f598432d24be6d5af6126240064a98e9408379bd651b553499013a9eaf025534d8fd5821f0521b96cec38588091e793deea1babae16c8b5860fe389d436ae1f010a5214f2298e2062b9c91244
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104461);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/20");

  script_cve_id("CVE-2017-12280");
  script_bugtraq_id(101646);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvb95842");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20171101-wlc3");

  script_name(english:"Cisco Wireless LAN Controller CAPWAP Discovery Request Denial of Service Vulnerability");
  script_summary(english:"Checks the Cisco Wireless LAN Controller (WLC) version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Wireless LAN 
Controller (WLC) is affected by one or more vulnerabilities. 
Please see the included Cisco BIDs and the Cisco Security 
Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20171101-wlc3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?88a89292");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvb95842");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCvb95842.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12280");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cpe:/h:cisco:wireless_lan_controller");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wlc_version.nasl");
  script_require_keys("Host/Cisco/WLC/Version", "Host/Cisco/WLC/Model", "Host/Cisco/WLC/Port");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");
include("global_settings.inc");

model = get_kb_item_or_exit('Host/Cisco/WLC/Model');

product_info = cisco::get_product_info(name:"Cisco Wireless LAN Controller (WLC)");

# Only model 5500 is affected
if (model !~ "^55[0-9][0-9]([^0-9]|$)") audit(AUDIT_HOST_NOT, "an affected model");

vuln_ranges = [
  { 'min_ver' : '7.0.0.0', 'fix_ver' : '8.0.150.0' },
  { 'min_ver' : '8.1.0.0', 'fix_ver' : '8.2.150.0' },
  { 'min_ver' : '8.3.0.0', 'fix_ver' : '8.3.111.0' }
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();


reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , "CSCvb95842"
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_ranges:vuln_ranges);
