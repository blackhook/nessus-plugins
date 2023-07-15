#TRUSTED 1c0f19e96c6849f2d7a6d5a22c55c16bc94fffcd0ae7e0b217c56b756380eeab5b85068d8bc66281ce3cf4b55a01392c5131b4bfb2bd9819e6784d8434ffb022353f588d8caa626a0860dd349332af59c9d6ab1e29c74e96cd1b24cea05d0e91b185dca600f599c341169db47ec33f89570f321767086f90df2f3cedc04105f121d913d6d4cde506b1619dcc375fc23baa74fe6d1f7e6775cbf1e74cdf604d6ff1bfb23f0feec5bff9d7a9428596acc3299840e7dc7e15ffb54ce2316ed5167458e776b29f05cc66185c0f8f07c31ca095b6c41075fa588ee0427f816837ac1713c2c2e433566ad4f11afd5a4898eae2f6544359c7b634b7f706c69a24b6a0fd1adb6369087a24f9f9f086f1abb5370013fd82a4942d12b7ef8db348883f50985b9f9f6dcc119396bd0010a43148d943349576396cfdab13d94d32c6ac4fd9f863da3dc1b08d3711dcd0a53ef486b32e1ff7e008aa6efe2879122d14875244085a27e0026d8ba45c7c7ae047922b382e350e287e381f2e5e939b4696edf65617dd6411b9b1f5b0836c33cd850a0ccbc0db749b6624f4c6c1e87e71365708da08a0dca7d903aa7d05819314c3e8e7f4915dd460349b70d1ee83a1275cde0d61a38d67576c754337b3a414b5d59898863e9ed6ff0184ad7a9e9b2ec8b93d4c543090a217fe7e478aba861f6790fb1898774dac226e4953aee121e17c06f95664be
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139029);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/29");

  script_cve_id("CVE-2020-3150");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr96267");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr96274");
  script_xref(name:"CISCO-SA", value:"cisco-sa-rv-info-dis-FEWBWgsD");
  script_xref(name:"IAVA", value:"2020-A-0331");

  script_name(english:"Cisco Small Business RV Series Routers Information Disclosure (cisco-sa-rv-routers-Rj5JRfF8)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Small Business RV Series Router Firmware is affected by an information
disclosure vulnerability. Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-rv-info-dis-FEWBWgsD
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eb4581fc");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr96267");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr96274");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvr96267, CSCvr96274");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3150");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(285);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:cisco:small_business_rv_series_router_firmware");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_small_business_detect.nasl", "cisco_rv_webui_detect.nbin");
  script_require_keys("Cisco/Small_Business_Router/Version", "Cisco/Small_Business_Router/Model");

  exit(0);
}

include('ccf.inc');

get_kb_item_or_exit('Cisco/Small_Business_Router/Model');

product_info = cisco::get_product_info(name:'Cisco Small Business Series Router Firmware');

if (product_info.model !~ '^RV(110|215)W($|[^0-9])') # RV110W, RV215W
  audit(AUDIT_HOST_NOT, 'an affected Cisco Small Business RV Series Router');

# RV110W affected version < 1.2.2.8
vuln_ranges = [
  { 'min_ver' : '0', 'fix_ver' : '1.2.2.8' }
];

# RV215W affected version < 1.3.1.7
if (product_info.model =~ '^RV215W($|[^0-9])')
{
  vuln_ranges = [
    { 'min_ver' : '0', 'fix_ver' : '1.3.1.7' }
  ];
}

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr96267, CSCvr96274',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
