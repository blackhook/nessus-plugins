#TRUSTED 730a9924a0de6be6e258fc612428c1bb3612c65ecef181f3e02b95bd43f99fcf07e68d011807a445101c6bcc321ae63c3c853740a94db121770133c9836366117d5fc09535db0dd7517d6a18ea8e78e9086ee017e8047440d436677ca2eabaa00187e46a379ac9c7bd3fe9039ada65a0e57d892ae03af8ffb9ac6a4a4232a07829dac0059a09b07ac1f2e927b6a9c88307cc88de1e006333af83d75b6ff1fe756a2120a67ab4de1405c96059e46177a76c406c119a9dfae8d9ce6715b025a09fbc0965d910722847afa8a36bf818a91cfd6bfb2bbfeac55b55996cac183c21b7ae97853ef7bb860ba8d25880777c604051bb50120a58666efa33520f530561150cbae44d003bf3ccf889e9376ed65af98456a5002a30f3439846f7f8dcb66769a0a728601c8a1f1e8f9e8b51fe08e685475a5761d7f7311cf4a58b9021919ba1e982595623f6bd0c6821ed9757a58ba292e505d2c210d65d5b3f0cbe1eac5fdd5e4cd90f5df11b5b1427309ecfa459e30f7a9211315acdf15dffa497b027cd905119e21457230f43b3f14c943e73441819d5b7a297474e227555ab576042e5b372c37df87465f7cae76ccc91ec590fceee3cd3924d1363bacfe371039d10731d4ef9e5f7e90986264b8e704992312bf35dd6647a6ef8518928c0eb330a9d3a5ae1b56855c594f7a3c3fc686153cf01c131343e66cf659a2512230d45cafe76dc
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(143234);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/01");

  script_cve_id("CVE-2020-3531");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt45219");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt45228");
  script_xref(name:"CISCO-SA", value:"cisco-sa-FND-BCK-GHkPNZ5F");

  script_name(english:"Cisco IoT Field Network Director Unauthenticated REST API (cisco-sa-FND-BCK-GHkPNZ5F)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A Rest API vulnerability exists in Cisco IoT Field Network Director (IoT-FND) due to IoT-FND not properly authenticating
REST API calls. An unauthenticated, remote attacker can exploit this, by obtaining a cross-site request forgery (CSRF)
token and then using the token with REST API requests, to access the back-end database of the affected device and
read, alter, or drop information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-FND-BCK-GHkPNZ5F
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cf10b275");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt45219");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt45228");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvt45219, CSCvt45228");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3531");

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
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvt45219, CSCvt45228',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
