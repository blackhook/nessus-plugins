#TRUSTED 5b4f114041a1bcbcde4e1d206fea89ed1f54c9af882c2c77ca3f20507af03ac9465fc61c36c38cad740215efbfca124c3124bb9c1327e50f97d6bcd519e3e4d4521031efef67ec8a7035347b7232dfd3f1da50b81d82d68dcd0b06909d6793e8f5217dc2dd545064df9630252626710848be39128f16c24b496212f83de268d4d6cba439412ab2864308fd9ed301bed366c978e9179076f4da5b2013317663c16d95329051793edaaeab8b68ba694b44ff318e41fc3f51fd531cd4dff43c6ccd4cea8a1edd581888e0a1d47a8b5c1c56e8932ed20dc93b003c0266be85243dcfa110db1519100b7092985ebb78bcc95452de66cce14256fde3893f58218460fc2495181a4a40e2ab48f7f19b0a2717dbe9015656f71d3886f22f5de9f0b849f6f27649c010f16ccca03df3438343f6af260b9085d7bf679bcf56fbef0c116a60dc44ea2659d3678ad792f991f75e05bcd02bc58691ed2ceeba2def03e948ac1d3a6cd0e1166becd7233583d56276eda7818784ade0380b1ce85e6a85b1abc6055ecdf9235142f49649b121c0815dcf525321dd0c1d6efacf6e5d135714f87833bf220caab6a378d6febc846b310ad77a359e336aead970acc1c03a6766ed8237f4f9f212751c31e688f9e051831666ce83ebf9a2657cc73fd4127d801b7a86ec2f61c2f639834256b35e3e9faded042e5d4a1e4937584bbe03a2b48a8a371ad8
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139927);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/29");

  script_cve_id("CVE-2020-3332");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs50846");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs50849");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs50853");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cmd-shell-injection-9jOQn9Dy");

  script_name(english:"Cisco Small Business Routers Command Shell Injection (cisco-sa-cmd-shell-injection-9jOQn9Dy)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Small Business RV Series Router Firmware is affected by a command shell
injection vulnerability in the web-based management interface due to insufficient input validation of user-supplied
data. An attacker could exploit this vulnerability by sending a crafted request to the web-based management interface
of an affected device in order to execute arbitrary shell commands or scripts with root privileges.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cmd-shell-injection-9jOQn9Dy
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?632564a5");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs50846");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs50849");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs50853");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvs50846, CSCvs50849, CSCvs50853");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3332");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(78);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:cisco:small_business_rv_series_router_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_small_business_detect.nasl", "cisco_rv_webui_detect.nbin");
  script_require_keys("Cisco/Small_Business_Router/Version", "Cisco/Small_Business_Router/Model");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Small Business Series Router Firmware');

model = product_info['model'];

if ('RV110W' >< model)
 vuln_ranges = [ { 'min_ver' : '0.0', 'fix_ver' : '1.2.2.8' } ];
else if ('RV130' >< model)
 vuln_ranges = [ { 'min_ver' : '0.0', 'fix_ver' : '1.0.3.55' } ];
else if ('RV215W' >< model)
 vuln_ranges = [ { 'min_ver' : '0.0', 'fix_ver' : '1.3.1.7' } ];
else if (empty_or_null(model))
  exit(1, 'The model of the device could not be determined');
else
  audit(AUDIT_HOST_NOT, 'an affected Cisco Small Business RV Series router');

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvs50846, CSCvs50849, CSCvs50853',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  models:make_list('RV110W', 'RV130', 'RV130W', 'RV215W')
);

