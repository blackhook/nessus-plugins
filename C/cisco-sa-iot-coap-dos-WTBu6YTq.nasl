#TRUSTED 422ce4ff469c848c53595477e55da16818f4027857cc9460cf38d215deb37fd79a9dab13c2d84c34bf821e8be9110af95a0be8350cc04b6cd39fd40dfe7963d75733ef1cb2b8578e6c1c046efb9c89a5e97b99b8c1a8db6616a1027fbf14081afa2a633dc977278a0073ddf14b0b0836419867366a497da916da2cebf66228a42bb33408f98560e9a1b70c67d4c07d4d6e7ee2b8bc1fbdbc28ada42646e15ca3643bb5bdfa81eb99f9a7dd575e86cb7f2646236bf2fce5f502760830679c1990e68f2c64b8a8fe25ba527613f46036518a5e6e41c8d24cee1af8ff24e0f8ce35e5c7f846cc2d61207c7993ce3ac9b4ef8d3fc6a3dbe8c6c8f97aecb126fee294d264fdcd2d804a20e12478f4f7c72e458cf69d5a40b41762f9cc5901e0689826295b30ae0c10a960cda1a418960f47663524ad4673c691b3b2e18df108dbff0978bd41d0e7a54e481291cdf5de669cea0e239ec64c80966a3f65d59e05c28dcbcab300565bdcb1d828d305cd5251d1b156cc6995885b35960c66f8eda5df7a1704f624b1248bdfbd53b0db110ad870bf647629965d059cabec9f6564751fd85e83175630d4b89ab43fa2eae516eabd6bf1eb4ed052785190d7783dd552168c16fc08b540ffe35e25ff6bdb437c7ea3f5fdf41f152fb51604a7408a95fc4cccda2e99d93f3bce34f5799babc905e2743a96d48779856e7e75b57945b602a33360
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(152131);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/30");

  script_cve_id("CVE-2020-3162");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs44179");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iot-coap-dos-WTBu6YTq");

  script_name(english:"Cisco IoT Field Network Director DoS (cisco-sa-iot-coap-dos-WTBu6YTq)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A denial of service (DoS) vulnerability exists in Cisco IoT Field Network Director due to incorrect handling of
certain valid, but not typical, Ethernet frames. An unauthenticated, remote attacker can exploit this issue by
sending the Ethernet frames onto the Ethernet segment, to cause the device to stop reload.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iot-coap-dos-WTBu6YTq
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9c4f2378");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvs44179");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3162");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:iot_field_network_director");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("iot_field_network_director_webui_detect.nbin");
  script_require_keys("installed_sw/IoT Field Network Director");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'IoT Field Network Director');
var vuln_ranges = [
  {'min_ver':'0.0','fix_ver' : '4.6'}
];

var reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvs44179',
  'disable_caveat', TRUE);

cisco::check_and_report(product_info:product_info, reporting:reporting, vuln_ranges:vuln_ranges);
