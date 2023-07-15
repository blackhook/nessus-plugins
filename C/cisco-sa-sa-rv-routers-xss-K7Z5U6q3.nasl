#TRUSTED 28e92fe84edc0a472de309aeeb5e2e2edad3d7229fb71bb45f4541be150962dd6dcd0f2c7b924b77777e25b76fd4d472dad7a40cc538ebdb13c5e4da8cb3e16fab8baf4ba3b955810199785c63290e3a3b7b792e6b8d94732e60248fcde27b732a2a7a1afec5c1bf0b9d6267e28bdba06c80a63709dbc4dec81a588f5a29fe1d49392bdc03ace4eaf5be51dfc0905f3e2cf3a3da5096984b532cf1fecf97592294e9ec5db8e579d2f0b726f01723f4d0fc628a59dedf825a97eb57011c1ff835c28d2263320c440d85fd479863b508633a08a4f785441dfba7871a445cf609bf57240e740eb9f42d51f5a3cc1f4732a2d345d1ae905a85a3334d85bd2d14dc78f13f16661cfdbae467b6bccdbb73f4019144ced6fdedc5d5f94ffd63d2f855304ccdaccbdad5460437c6436ac287e3934c279db19c8980f7a70d70c36764ada0993319cb44c0c4c54bb93b81128295f43da05173713a3696bf9b7c824e82d63a6075a7a944e76b8a9869632af73a9aacd7f7642a9d25e950c1c08cd94879ca8c59a5dc82ea006a63afd90b1db10e46482c8038550065c7287b3dd5aa5c8ec5e67aebcc7467976fb032ca837461bcaf1a77a7661db1f31cf69c8e82dc166a245c8ceccadef6d0cbbc947b48588e0d0c27815fd78ffa81345a304e96a05db6c8d57d593a565403400e10f70a04663e2aef203a11208280c30de03169917cc24649
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138327);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/29");

  script_cve_id("CVE-2020-3431");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu06343");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sa-rv-routers-xss-K7Z5U6q3");
  script_xref(name:"IAVA", value:"2020-A-0285-S");

  script_name(english:"Cisco Small Business RV042 and RV042G Routers XSS (cisco-sa-sa-rv-routers-xss-K7Z5U6q3)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Small Business RV Series Router Firmware is affected by a cross-site 
scripting (XSS) vulnerability in its web-based management console due to improper validation of user-supplied 
input before returning it to users. An unauthenticated, remote attacker can exploit this, by convincing a user to 
click a specially crafted URL, to execute arbitrary script code in a user's browser session.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sa-rv-routers-xss-K7Z5U6q3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9b6d4ec0");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu06343");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu06343");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3431");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:cisco:small_business_rv_series_router_firmware");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_small_business_detect.nasl", "cisco_rv_webui_detect.nbin");
  script_require_keys("Cisco/Small_Business_Router/Version", "Cisco/Small_Business_Router/Model");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco Small Business Series Router Firmware');

vuln_ranges = [
  {'min_ver':'0', 'fix_ver':'4.2.3.14'}
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvu06343',
  'xss'      , TRUE,
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  models:make_list('RV042', 'RV042G')
);
