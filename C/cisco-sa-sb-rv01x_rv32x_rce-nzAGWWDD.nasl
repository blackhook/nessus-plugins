#TRUSTED 085cf7a9999bbe1d5fa81126cfbf2a223f840bf5eb8c8bd34963c464655ef9d16364ae48a73b6c0accdb1396ce69dc4940a49ef9b8a3c5340fd641ab8f97801aaf36da48e938f7561722c10c6f859c953c1c9a556fc99559ecf337a720823f7fe5af786728a435c9c64193472ad70e390f4c316892f3c9c9fbc59e7343c231db90f64ebc02347e5382b20972d1669fee765b428e6a35c4b8ed7ffe31ad0c97f1398a9f79ff2822e2c15a8801f1a24e351de216edfc932caec913c39894209e852eb4015320311df0b7c1d02030e07b873137a468f0d8b5c771ec3dcaaf1370bc95f4b25a8a675429b807d9115d6326ae595465d0b9672dace08cad74080c8ec397347b7a71694dce278a32c9c951b7fd1048d6800d2d43fd96e7e5db3da6bfa4e4dda0c73004664ed5cfade48d746f19c32db0efe2ca1a6c3726d0bc9bab9530e58d1519afad86a35ae1fd3cf9c5418253f5f4689871632f99343e8373d692566e58ccb131b2180229c39bceb01d30b98dd4c0806162103398b7cea255556befe517102a6e8fa28c1ad68f1f4e9466294fee23bfc14984b02fd8dac59d9acd343e36ab76a9a656d7f27bc8e81db1ad0cbfc3748345d643a7e7ce94439fd219cb118ee7ec25208fc2389005639f4c1ba5878feaf4ef05c1cd3d6b0fcf3ed7c3a25a4833d4070e8c33a7bf1dfaad1c3e2b6ff6ffa87e4d5aed111e74e4410846cf
#TRUST-RSA-SHA256 52eaf3b4acbad92e559bb363ad6f17d76e1ce26119aae22918f4ca73a2289332b36aa2fe7cfe81bd4171795aa50ae0f3c173e5b69dba7387557e7cca21247af2557e21d7084cd758dbe37c3d111ccbe7fd85f4c64620e6302e6747531403abcb3102e9307dc262893f5f4c73f2bb28736847d7fe9aa86c0adbadce6a216d40d7d18671bbd406457496fd33269db102837c07b843ee07a627cde617e1276796a7265df5b54711318bfd15e890222a47d6dccaef157048c217d53690b5a271019c38df0fcd63de4d22bb31fa305747695de5049abd44920c03ec82e464ca11bd1ad28d37a7c07001a11cffb50d691d8013c174aa289b7c02980decd0c3d85baaa7621aa5f8665e01fba01bba5825d6282baccb8a3bd694e418ea78293ef02cb475d28187d210469e4e69d3acb08e10446f20076ce14e13d63493b0451c6c616774a42eb09baaddc1b781a3eb09fad332a1ddb2d864baf3bc63f2d275637fab7cbd01c0a38c87b1c4ae3dab9549e88513bbb2743ff5f7a793fb5a7cd8004647354bff57e6f8678ea0410d8ea4312b035fabedbf854139af7999102a7cf751ba2e281f0378fbf3a1fbbc8ed70c95d74f71d3e875b4b366ee53941dfb5a111e4b8a6d03eb0cc5e95cea1afbb7319afb0512715d61dcc5cd97a04f28340f13062804bd9fefc88f4f2781b48524e52b0f9088fc0840156ce1af47126f5a49ab985c020e
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(173969);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/12");

  script_cve_id("CVE-2023-20124");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe67655");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe67659");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sb-rv01x_rv32x_rce-nzAGWWDD");

  script_name(english:"Cisco Small Business RV016, RV042, RV042G, RV082, RV320, and RV325 Routers Remote Command Execution (cisco-sa-sb-rv01x_rv32x_rce-nzAGWWDD)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Small Business Router is by a vulnerability. A vulnerability in the
web-based management interface of Cisco Small Business RV016, RV042, RV042G, RV082, RV320, and RV325 Routers could allow
an authenticated, remote attacker to execute arbitrary commands on an affected device. This vulnerability is due to
improper validation of user input within incoming HTTP packets. An attacker could exploit this vulnerability by sending
a crafted HTTP request to the web-based management interface. A successful exploit could allow the attacker to gain
root-level privileges and access unauthorized data. To exploit this vulnerability, an attacker would need to have valid
administrative credentials on the affected device. Cisco has not released software updates that address this
vulnerability.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sb-rv01x_rv32x_rce-nzAGWWDD
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d9c558d6");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe67655");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe67659");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwe67655, CSCwe67659");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20124");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:cisco:small_business_rv_series_router_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:rv320_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:rv325_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:rv016_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:rv042_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:rv042g_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:rv082_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv320");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv325");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv016");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv042");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv042G");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv082");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_small_business_detect.nasl", "cisco_rv_webui_detect.nbin");
  script_require_keys("Cisco/Small_Business_Router/Version", "Cisco/Small_Business_Router/Model");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Small Business Series Router Firmware');

if (toupper(product_info['model']) !~ "^RV(32[05]|042G?|016|082)")
  audit(AUDIT_HOST_NOT, 'an affected Cisco Small Business RV Series router');

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_HOLE,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwe67655, CSCwe67659',
  'disable_caveat', TRUE,
  'fix'           , 'See vendor advisory'
);

cisco::security_report_cisco_v2(reporting:reporting);
