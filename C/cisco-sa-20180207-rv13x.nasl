#TRUSTED 2671a97d6a35459e3ade403497cbfe92cfbc0b924b91d91823841bbe79dc8b0cc169be283d0046327eb8d2f8e6ff33a8d84fac305e7ffaebcbff07a8f1807b3279897ee97d216f5f7bd4bbdeee66cb52b4e3856b002ed9d1acbefe6ec98451ffbb9e4f81e75437f60752c3434ed0ec580c68ac485f232d53e6b727d6621271bd4e5ca8b9afa79dec28db2418cd6e1cc6040932a356962645a5a61777eaef8d79db87c7e95f13fc6e2420c7c5b61d2eeb956fdaafcf2e5dbeeead8f2d5b7327e69faea1ae412cf413946948cbf4172cda12d7951a93d5945106f5f2824af8d79cf0527efb7e3ce6187cd55d85fc3741761f582db1ebfa6414ebc069365ba7d094ba36f21cdf93a6067640a4c8f5368a903e5c284cfce906e904ab4d9fa3a5af3a84ce5b3d93930651b2e466140044738c343beb9fda7cc2c865292d3825bea45e3e427a7e0e29df185e4c3765b9dbb55512da059afdeb7e902dd2a2e734d6378bccfb80a2e13e87eb16a6b1a9ca47b580e4c2b003a22b275c2a9cf0da489d2cbd73eba032aea5c3eefb0d6cbb1af301ae324709c68691af98e71757933736b2bd8c29c47aa167ac7ee0d6953c0563795330a29f2033d38126b376a168c4101dc8d138a13338dde7582b16aad8593c4a3671535aa896ec4c59923f54e740e04e4b906dc32959d0a2f166cc86da155bc132f78390124988a788d69b54e78c5d7ba2
#TRUST-RSA-SHA256 20ece0d7562c809a36fce51cdb6eb8220dc104de1fe4c0035a25f5b733f667aed20575d13e4433ee33685fb924c71818771deb0168978ee5443d2bc9ad4e4b289203baa1e3b2f501bc47fac9c17e74d4f9789b22e1414f45262bc20d595f9df61b24445980ea0a231e5987ea2c75e214fe04d7fb26f1f7edfcb72c44ea15e0f9ade1758d87e9d6dad069cd8a42d18044448ce1b68df814b3d450a68c44cdd46f65eaeef6d2cc1b1c461cf43064bc79d3f40154a9280cf4e30b2511d8e2043d02e2a99d0b8e2b1abbb62750c2ad565f5b865d08d1664a31a0c10bc536c6e5b90f671c9292f7dd450a60ae9f2696f9edf7e27ebeb26ebc15fa5ea8fed57bcc0e2992b4307808ab4cb6ef165750e330624d0f5884a61484d7e0fb136326a859a89176d99d281e90d0acecd1e6c7a3e5ec33174999a9f7a03f532f205e6399d6034f50e53477a0b1221e582b4da0472ccab397a36a60488096c8e8b465c17b86ea78c0648922ba652bc7caa3761c4cdeede556e43a069bc806737f4beee33d1d53bdeeed4eb23e6aae8658fb1eda09b577ed27a824f84450c0a37fb590737abeed3fb7ee89a6a9b7000b650d845ecf1dba4c326906e6b87be28deb6ac9b5074c0989aade6cef68a5b0070ee732866556d95a502832770202c889940f93b4e1bc182b4a37f9a8ad19c6ca0d4b84c91b923b25e1bb8e669f32f7077dd642bac8c632b4
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(129781);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2018-0125");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg92737");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh60170");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180207-rv13x");
  script_xref(name:"IAVA", value:"0001-A-0010-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/15");

  script_name(english:"Cisco Small Business RV132W and RV134W Remote Code Execution (cisco-sa-20180207-rv13x)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, this Cisco Small Business RV Series router is affected by a remote code
execution vulnerability. A vulnerability in the web interface of the Cisco RV132W ADSL2+ Wireless-N VPN and RV134W VDSL2
Wireless-AC VPN Routers could allow an unauthenticated, remote attacker to execute arbitrary code and gain full control
of an affected system, including issuing commands with root privileges. The attacker could also cause an affected system
to reload, resulting in a denial of service (DoS) condition. Please see the included Cisco BIDs and Cisco Security
Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180207-rv13x
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fdf80fdf");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg92737");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh60170");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvg92737, CSCvh60170");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0125");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:cisco:small_business_rv_series_router_firmware");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_small_business_detect.nasl", "cisco_rv_webui_detect.nbin");
  script_require_keys("Cisco/Small_Business_Router/Version", "Cisco/Small_Business_Router/Model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Small Business Series Router Firmware');

if(product_info['model'] !~ "^RV13[24]W") audit(AUDIT_HOST_NOT, 'an affected device');

vuln_list = [
  {'min_ver' : '0.0', 'fix_ver' : '1.0.1.11'}
];

reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_HOLE,
  'fix'           , '1.0.1.11',
  'version'       , product_info['version'],
  'bug_id'        , 'CSCvg92737, CSCvh60170',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_list
);
