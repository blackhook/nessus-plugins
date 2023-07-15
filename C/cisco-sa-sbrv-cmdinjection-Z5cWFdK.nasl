#TRUSTED 2712a0d30959eb9178dfe78ed95fd63930bdd8348fb1d598237783f17c27a26b7ccc08eefa37da1edc53f8701af5f5a6cbc6d1060e1d3fb557afadf3ef629d167905358c5a3621461451cb854948cfac26b5eda3e01f4928d6e49f30039b61d9bd372f94810a5f00a72ceabf6db9f92a6f19ac1b742e80ad7040b758b661d2fafd29b024432208cfd356bb517bac7b9ca76f249aa3833a332c66c68431ccc78bccb41fd7642be11228c5d23ea8b39a75972768d02b6c13bbd65c3590245bca1ae24e9b121ada1d70d636ab57f3578508847d859f27940b1f4897e4b40c8095ade7ceee3789669dbe930dd9ea5b0a91026fa9617c38febf3b5215e05e21d6beebf52acda6661b0527d8e2952f39c380450591246ab3e806e16060a74e0b311a3595c2fe97e16dbe1b5e4a49bf4e5d5190bc4c0c9af36648c5787deda1b7b2cb6b17f86ecadfd10e8f853de9b2ea9629b98fcbf3ef96641f8532d3314b2b644fd1b389e13c6f8d8655041a6af54f1ef7631753ec9ce186cda9062d28a10d3ad53bab0849edbcb5f47691c184138fa2fc3f95bdb8432685b5c4b635c6d9b11a331b73fd9ec0fd1c503fe65caa1eec2415cf3c61bef4772f38c03a29dec9f556657872d251f37e9cc9c0cdc67a4f59fb3e884b0af39f213047ab99b6bb3e2053d6d7fa304d38ded9df101dc2c9bc6c827d6923811d5d7a5d005407dcc17c3ed11b10
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154932);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/09");

  script_cve_id("CVE-2021-40120");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz75703");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz75705");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sbrv-cmdinjection-Z5cWFdK");
  script_xref(name:"IAVA", value:"2021-A-0534");

  script_name(english:"Cisco Small Business RV Series Routers Command Injection (cisco-sa-sbrv-cmdinjection-Z5cWFdK)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A command injection vulnerability exists in Cisco Small Business RV Series Routers due to insufficient sanitisation of
user controlled input. An authenticated, remote attacker can exploit this, to execute arbitrary commands.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sbrv-cmdinjection-Z5cWFdK
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?41785694");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz75703");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz75705");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvz75703, CSCvz75705");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-40120");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:small_business_rv_series_router_firmware");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_small_business_detect.nasl", "cisco_rv_webui_detect.nbin");
  script_require_keys("Cisco/Small_Business_Router/Version", "Cisco/Small_Business_Router/Model");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Small Business Series Router Firmware');

if (product_info['model'] !~ "^RV(016|042|042G|082|320|325)")
  audit(AUDIT_HOST_NOT, 'an affected Cisco Small Business RV Series router');  

var vuln_ranges = [{ 'min_ver' : '0',
                     'fix_ver' : '9999999999999'
                  }];

var reporting = make_array(
  'port'            , 0,
  'severity'        , SECURITY_WARNING,
  'version'         , product_info['version'],
  'bug_id'          , 'CSCvz75703, CSCvz75705',
  'fix'             , 'Refer to the end-of-life notice for your respective product',
  'disable_caveat'  , TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
