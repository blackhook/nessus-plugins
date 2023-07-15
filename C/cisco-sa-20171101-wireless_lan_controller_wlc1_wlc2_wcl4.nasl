#TRUSTED 72ea48ed47403133b214cbef2d6d78211a128d0d164118ff857b7ce5488e965d9834142c283fa3b7dc9f8acc691296642cea481147febeb21088875c3f0968c91cdbf2dc607e321580884e1842e9bc01fb78e04bc3eb6b4d656e0c164074f37f98b7cc72e709daef4ee86aad97a796c459f72bab37078846fafa5198a0f4e43804462c86133426f8f7c49181ec650486c5315c6630c18d9b38da54a523121f162c7f646578c9a6916c2d9e23cc652ecca3b2a8cbaefb63784bd18f267c4291be8ad2572acc5580e46cb2f83e5a94d8442733fb4032cacd9d4988de6bc98a9b454962a79eddc475a364aad8c3695dce83c6ea1692ec01bcac60994120f15a59cc9dc2a15cc3d2485022f012d51ccfaf3a44944f8911bcdc955808e5596bc80cb639eaafd43763a68f801ac23b349695ea34cf53978dcc49b10d9b8dfc86f4825c338dbb58c94cc5c3de916306292947cf80652727e18a6fa3221a6ae221efbaa1d6a978132a7a058d01136a56fffec67be66b53232e0faff39f010d9f8d883badf349fbb49811a710b978e76c0f1838f56490c56e7adf05dd9eb9c9107b35737a34bdeda5e19c1c6b44a14136410b3dc5398d27e281f9b785ec9f23078fbfb60982fb97cba7b9ce5bc2592b10512399ebe753e53d85987105862a2fa591ebef361d7bee9188e8c8cf3d53fb01a2c4bf042d0bef9b6d54d9adb1aa34ab6b030f2b
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104460);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/01");

  script_cve_id("CVE-2017-12275", "CVE-2017-12278", "CVE-2017-12282");
  script_bugtraq_id(101642, 101650, 101657);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvb57803");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc71674");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve05779");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20171101-wlc1");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20171101-wlc2");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20171101-wlc4");

  script_name(english:"Cisco Wireless LAN Controller Multiple Vulnerabilities");
  script_summary(english:"Checks the Cisco Wireless LAN Controller (WLC) version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Wireless LAN 
Controller (WLC) is affected by one or more vulnerabilities. 
Please see the included Cisco BIDs and the Cisco Security Advisory 
for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20171101-wlc1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4b1ceb09");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvc71674");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20171101-wlc2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?756f0476");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvb57803");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20171101-wlc4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a20a37d3");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve05779");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCvb57803 / CSCvc71674 / CSCve05779.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12275");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:wireless_lan_controller_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:wireless_lan_controller");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wlc_version.nasl");
  script_require_keys("Host/Cisco/WLC/Version", "Host/Cisco/WLC/Model", "Host/Cisco/WLC/Port", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");
include("global_settings.inc");

# Making this paranoid since we're unable to check the config for SNMP
if (report_paranoia < 2) audit(AUDIT_PARANOID);

model = get_kb_item_or_exit('Host/Cisco/WLC/Model');

product_info = cisco::get_product_info(name:"Cisco Wireless LAN Controller (WLC)");

# Only model 5500 is affected
if (model !~ "^55[0-9][0-9]([^0-9]|$)") audit(AUDIT_HOST_NOT, "an affected model");

vuln_ranges = [
  { 'min_ver' : '7.0.0.0', 'fix_ver' : '8.0.150.0' },
  { 'min_ver' : '8.1.0.0', 'fix_ver' : '8.2.160.0' },
  { 'min_ver' : '8.3.0.0', 'fix_ver' : '8.3.121.0' }
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();


reporting = make_array(
  'port'     ,  product_info['port'],
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , "CSCvb57803 / CSCvc71674 / CSCve05779"
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_ranges:vuln_ranges);
