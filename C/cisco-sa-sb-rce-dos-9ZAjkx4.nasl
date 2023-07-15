#TRUSTED 0818763da679573c7875e2fe99d0a6db9da1fa8bf5b69bf0c73de336a42f9b7616a32397ef1dd254697b9bcb0c5f4499ac2c18138804bcd6ad51b240a0013b40b7b24c4711ce56fd02ccc70f4eb86669bbb94f77dbf7b61733d33db1294e460d05d19a1f9687a078d616b9b189a373e676d0f7fb79d07370ceab04fd297e6f81dc8a4852c269ca0c415d4a8535554e3d5a99cfbfb9766aadfaf9ff766db56328951ed34286fb0d00e6300110e440ca85ed1d82043e3f65004c83dab265ed5b669a960bce6b05b8c3ce7c2a78d895f453700d8cfa1ae7dd64ae061048a560ab00d5a497a4dee1aefec51f7738c3762e9c102baf08c3b19a47aabe59416201d0c642ef470f0a3142fd8799b473f016e431a31d4f426a55804d512f87efd3418d13c76d35ecf6724e1afb0783a2ac0b4c90ff652e4995af9e99558ccfe8dd1b153754ded1c29f04eaa137fbd3ed3812ba676982ae62060ca809956f8c95a4f7edd703bf284b08dd619d38dc8d7f6a07f847885cb0f825b4f3d951e376ff977bb3523b459880e37bdf338335af69c1ce2636fdb45bc76bc41099a387f0a0e2edddb77b6039fa985bd5e90fd1c8b1dc4f3c28fa4ef9b43b7a294618226bfe6d140f4ed2a1ecd0ea48095847388be6ba53d13fbf7eae6eaaf6ae566cfb10334bdec3f466ffc2ff0761c956f66372729753c248c9c918894776d3cd506dbec3af17935c
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140452);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/29");

  script_cve_id("CVE-2020-3357");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu36543");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sb-rce-dos-9ZAjkx4");

  script_name(english:"Cisco Dual WAN Gigabit VPN Routers < 1.0.03.18 SSL RCE and DoS (cisco-sa-sb-rce-dos-9ZAjkx4)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Small Business RV Series Router Firmware is affected by a RCE and DoS
vulnerability in the Secure Sockets Layer (SSL) VPN feature due to improper validation of HTTP requests. By sending
a crafted HTTP request to the device, an unauthenticated, remote attacker could execute arbitrary code or cause the
device to reload, resulting in a denial of service (DoS) condition.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sb-rce-dos-9ZAjkx4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a0e9372a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu36543");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu36543");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3357");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:cisco:small_business_rv_series_router_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_small_business_detect.nasl", "cisco_rv_webui_detect.nbin");
  script_require_keys("Cisco/Small_Business_Router/Version", "Cisco/Small_Business_Router/Model", "Settings/ParanoidReport");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Small Business Series Router Firmware');

# Plugin is paranoid due to lack of GUI config check
if (report_paranoia < 2) audit(AUDIT_PARANOID);

vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '1.0.03.18' }
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvu36543',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  models:make_list('RV340', 'RV340W', 'RV345', 'RV345P')
);

