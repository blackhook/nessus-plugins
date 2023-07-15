#TRUSTED 17f6c51bca12fcc226e88acc5fe3d9efc35835fecd9ab0285783fe84ff4e2a43ab55ff5dd754c4d725688ba35c7a3ba51cc14675d254139119f30a4c1849e218b74d51ba5263b32de1b2bafa04d21cdca43386f1563fb224fc605406c3249e99ecb77f5979c97e3609788dd086cb39b07ed7390660ca7c5b4763f9f974cbf6ea7d49de12233d1b191a9b2cf8e5c0e4a3a92ddcd7b20556552fcca533a8aba3c576e833e12de442cc87c6b5a6c7082fd8bb0573c4e8662418e96e297591ef0dc6e267d9a2e924582c090836681fa3aa29f99331ccf3a42fcbdfd4a1c0f6fc860a232496ed2a83c9da235ccd163b74664ffb5b92b31fc34ba50e86f669bfbed2701895e001f395ed46b2f8981adf66ac4dd71396f29e55776260ea14d7fdcf6f057f36cd5abb0856447772471038b9e78eff5cadb01ecd8a576946e15f48e9a8a63b81bde219099a5e5c8e3beb8776d859f3b6e50cbdfc2fcffff5806e30e38d5ad91ffa2b45564bbd46d7cddba67660719a96d26d41bea841f609105f7d2a460e62e7e50d0e8823639a79cd2bc9bda0667011eaac2dde597bb37585353898530fb7c44599a5ec1a96839b063db28fef1672576393607ac0db1ad965a145833a0e7ea2a722261ca8233995d6daeb4d8981c14a9eca4e72bd88a1251a0411d21b147eec4d594e7ab0b4be561df092e0e6a5bc7a27a286c6ed4a9de8a53897382228
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139067);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/29");

  script_cve_id("CVE-2020-3145", "CVE-2020-3146");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr94660");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr96222");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr96225");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr96232");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr96235");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr96242");
  script_xref(name:"CISCO-SA", value:"cisco-sa-rv-rce-m4FEEGWX");
  script_xref(name:"IAVA", value:"2020-A-0331");

  script_name(english:"Cisco Small Business RV Series RCE (cisco-sa-rv-rce-m4FEEGWX)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Small Business RV Series Router Firmware 
is affected by an remote command execution (RCE) vulnerability due to improper validation 
of user data. An authenticated remote attacker can exploit this, via HTTP requests, to 
execute arbitrary code with high level privilage. 
 
Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-rv-rce-m4FEEGWX
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c3bf0372");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr94660");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr96222");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr96225");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr96232");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr96235");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr96242");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3146");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/29");

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

# RV130 & RV130W affected version < 1.0.3.55
models = make_list(product_info.model);

if (product_info.model =~ '^RV130($|[^0-9])')
{
  # RV130 & RV130W affected version < 1.0.3.55
  vuln_ranges = [
    { 'min_ver' : '0', 'fix_ver' : '1.0.3.55' }
  ];
}
# RV215W affected version < 1.3.1.7
else if (product_info.model =~ '^RV215W($|[^0-9])')
{
  models = make_list('RV215W');
  vuln_ranges = [
    { 'min_ver' : '0', 'fix_ver' : '1.3.1.7' }
  ];
}
else if (product_info.model =~ '^RV110W($|[^0-9])')
# RV110W affected version < 1.2.2.8
vuln_ranges = [
  { 'min_ver' : '0', 'fix_ver' : '1.2.2.8' }
];
# RV215W affected version < 1.3.1.7
else if (product_info.model =~ '^RV215W($|[^0-9])')
{
  vuln_ranges = [ 
    { 'min_ver' : '0', 'fix_ver' : '1.3.1.7' } 
  ];
}
else 
  audit(AUDIT_HOST_NOT, 'an affected Cisco Small Business RV Series Router');

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , "CSCvr94660, CSCvr96222, CSCvr96225, CSCvr96232, CSCvr96235, CSCvr96242",
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  models:models
);
