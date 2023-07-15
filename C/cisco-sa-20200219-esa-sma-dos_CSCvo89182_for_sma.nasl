#TRUSTED 03ff58ef6f01be1c3a3eb220fd163d9f31437bbafad87d3bf61a0d13ca167b29a8ad3b02176afd8cd0426a4b77d38ac87d24ea2d458d45c40d39319a0f13d7ef2d458b477b0a738f613d1b953000a58cb7795050febab4602c353db7757af24716b4dfb35bc37271f313d7056a43847d03a4e71e8cca69db404bb9e74bfa4e8899e10a20044a6b7e7e4d90a7e7e58a26d578f11da8a3c85a3f3f3ba829bf0111b09aa80bdeaf0422292e1bea4dd92856e319195d50bff461dfdc640cb6e7bc71b7a20a9eeb7addc804ebc932e3fc10148227276f91d50049266c0d1cf150611eaaec31d15c29abc4f344c08d0a42922e93834569c5a36ec7099794dff4639e865a7bd73f9f9f630c85271fff39b91c699da2ff0bd646f4feb071c1aa9bc2333a9961b9e049ab27f747ea1c6f7faea2d661e28346cb17a0e3ea1601fb5f6153791eb167ecd7a007af196313d1fa75606e91bc76cf2d97fe10687a09f10775aa14675f1542c2067e709b8ad73eedbe9a28fdabda523874db9b47f782d4ada17a0d4ca3caad8abaa9fcbaef12d5ceb192f260e60c2875dcb84634edd55b1c38ff81b2435fc917021af517ed5c93a8d8320d6ef23cd9b0d579264b833806ef3a252cc63cb7fcf0c84de13253dde2546760e64b7b1f618eaa8be66fd3acde2e863240f9d51f90ba0d1ecb4b558a3ed12fdde6bd16071c2eb26182b8fa9447135bda8d
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133960);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/16");

  script_cve_id("CVE-2019-1983");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo89182");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20200219-esa-sma-dos");
  script_xref(name:"IAVA", value:"2020-A-0045");

  script_name(english:"Cisco Content Security Management Appliance Denial of Service Vulnerability (CSCvo89182)");
  script_summary(english:"Checks the Cisco Content Security Management Appliance (SMA) version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Content
Security Management Appliance (SMA) is affected by an input-validation
flaw related to the email message filtering feature that allows denial
of service attacks.

Please see the included Cisco BID and Cisco Security Advisory for more
information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20200219-esa-sma-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b12c8fec");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo89182");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvo89182");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1983");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:content_security_management_appliance");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_sma_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Content Security Management Appliance/DisplayVersion", "Host/AsyncOS/Cisco Content Security Management Appliance/Version");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:"Cisco Content Security Management Appliance (SMA)");

vuln_ranges = [
  { 'min_ver' : '0', 'fix_ver' : '11.0.1.161' },
  { 'min_ver' : '12', 'fix_ver' : '12.5.0.633' }
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();


reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCvo89182',
  'disable_caveat', TRUE
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_ranges:vuln_ranges);
