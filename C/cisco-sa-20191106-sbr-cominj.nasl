#TRUSTED 96b41bef41b903e3dc1255198ee83c3a29057eba376bbb1852c71f1e72b1e16608c710ec1adea7c732933d6858d432a9c4315e8d78070fc4e1b68c5ef88390080cae9cefab190be7c77b7b636e54a74b048d88f4a8dddf3e38c4c97fbcd35fe3db71e168895268739e44b6173e5c5d65f0352db343bed4282824ad90b07bb920702fb9374dea8b0fe68f1f280b4e223e71db0957dbe7b3cfd9babac5909bfa68f8c8089fee9ea39c5be8fa5f45c1bd1a64607747db93988b8e77e27c097445d4c845b4133723d973271acf9cc13b8f3419b1525f69fb1c541f834987bf3c2c40c441397de699bd0ec25b6654f8806e7b64ed2a3c3922204ca510d1a4bae5fd63396c5c462fbddcd0b51e986b0fece0bf9540edb3fd70bd9eec1e6048ed207e400824eb9a1dd716718da8ecb3dfcb0e8c598bc884c2a0ef6f5f2b829b0790378cb75512df9e695e9c6bc541f37c1839f64936b3f44574496ad3aa85117c91fc52e77c0103287c29f31920b3e942019eb6359754b97c63d84f71a40696f89510d04fbf619148766fa6358fb45e7ce4bdbd0c7a5cd92e2beb9b1d83c656a274bf883e925f9cf4f354bbc7f4ed1322baf3c6038062192d5030df59caf9089d7e54c325d94c8a12f8c8d178b2ce687f22f118f06186fdefe29a6a7ca94b97f5f82425292be0699cc5266e8deb4fbd8b96740c7065f6beddd92955624cc2e3ec35b556
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(131231);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2019-15957", "CVE-2019-15990");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq76768");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr39939");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191106-sbr-cominj");
  script_xref(name:"IAVA", value:"2019-A-0429-S");

  script_name(english:"Cisco Small Business Routers RV016, RV042, RV042G, RV082, RV320, and RV325 Command Injection Vulnerability (cisco-sa-20191106-sbr-cominj)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Small Business RV Series Router Firmware is affected by a vulnerability.
Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20191106-sbr-cominj
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?38591e1a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq76768");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr39939");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvq76768, CSCvr39939");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-15957");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:cisco:small_business_rv_series_router_firmware");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_small_business_detect.nasl", "cisco_rv_webui_detect.nbin");
  script_require_keys("Cisco/Small_Business_Router/Version", "Cisco/Small_Business_Router/Model");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Small Business Series Router Firmware');

if (
  product_info.model !~ '^RV016($|[^0-9])' && # RV016
  product_info.model !~ '^RV042G?($|[^0-9])' && # RV042 / RV042G
  product_info.model !~ '^RV082($|[^0-9])' && # RV082
  product_info.model !~ '^RV32[05]($|[^0-9])' # RV320 / RV325
) audit(AUDIT_HOST_NOT, "an affected Cisco Small Business RV Series Router");

# RV320 and RV325 affected version < 1.5.1.05
if (product_info.model =~ '^RV32[05]($|[^0-9])')
{
  vuln_ranges = [
    { 'min_ver' : '0', 'fix_ver' : '1.5.1.05' }
  ];
}
# other models are affected version < 4.2.3.10
else
{
  vuln_ranges = [
    { 'min_ver' : '0', 'fix_ver' : '4.2.3.10' }
  ];
}

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
'port'     , 0,
'severity' , SECURITY_HOLE,
'version'  , product_info['version'],
'bug_id'   , 'CSCvq76768, CSCvr39939'
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_ranges:vuln_ranges,  models:make_list('RV016', 'RV042', 'RV042G', 'RV082', 'RV320', 'RV325'));
