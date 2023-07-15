#TRUSTED 6b82d619572cb7e967438c19efb90b70ed0462b556041933dc4a2ec91e850ef6d05839475ab6945d16018ab27244ba1957b9ab0f2b0a88a1648ad69b62212d0865c55387a3f680b12a5eaab63d873adb1d51f77b55d4d3f29a2795897636a1096bfce598830b7202a097c23fb53444c4f3753f701bc7b5ea5ff0f35a2e02cc7e22ecd995b50f47a0498d5e097a57bc533bf97df1be2a96be25fb3fe00bccd19e43ef3bba6bbfac95c42561d88f3f7c65e080dfaf367e2565769bd4006944c0352f2c95edc4da7f6aef92e1b834e6a8ef0ebc845f7afcbff61129fc9cb2a0a3814c88a6c4ab138b57876d4fe3cfaae5c3a98f3fdf2501fbe69456ed776ae98bc1e853cb04629c63360d54ce3f98ce4de8f70b305d2490377b570aa8e8cca1d6234c359b436b1fce263701d27d0a0a610752da33ca0e014049b232a756cddc162cac4c4f4d1e317a4f55871f720e05f0e2833c3777aa441d9b22e88fcca1809d826220cccabcc2c09452ef4648e6ff57ce6a2a666960963f5326c02ae1d6774679e89f6a6ba91734af779c16477506cee2570ebe43a3f0aa28b60305bb23529c6e2cc51e53e3709699ee233b888800358c02476e493ee31a76e67da808b906c8dde0963dd7a0c299fdd1ab29a5b0811509d48ed500606d8f45d7d24203d7a00533379b4c9a520d92636eedcbdd036c494b8fdfd48ec03a543ecb6f9525e195c51d
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140272);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/29");

  script_cve_id("CVE-2020-3451", "CVE-2020-3453");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu40103");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu49391");
  script_xref(name:"CISCO-SA", value:"cisco-sa-rv-osinj-rce-pwTkPCJv");
  script_xref(name:"IAVA", value:"2020-A-0401");

  script_name(english:"Cisco Small Business RV340 Series Routers Firmware < 1.0.03.19 Command Injection and RCE (cisco-sa-rv-osinj-rce-pwTkPCJv)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Small Business RV Series Router Firmware is prior to 1.0.03.19. It is,
therefore, affected by multiple vulnerabilities in the web-based management interface that can allow an authenicated,
remote attacker with administrative credentials to execute arbitrary commands on the underlying operating system as a
restricted user.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-rv-osinj-rce-pwTkPCJv
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?35b3f57b");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu40103");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu49391");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvu40103, CSCvu49391");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3453");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20, 119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:cisco:small_business_rv_series_router_firmware");
  script_set_attribute(attribute:"stig_severity", value:"II");
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

if (product_info.model !~ '^RV34[05]($|[^0-9])') # RV340 / RV340W / RV345 / RV345P
  audit(AUDIT_HOST_NOT, 'an affected Cisco Small Business RV Series Router');

models = make_list('RV340', 'RV340W', 'RV345', 'RV345P');

vuln_ranges = [
  { 'min_ver' : '0', 'fix_ver' : '1.0.03.19' }
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvu40103, CSCvu49391',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  models:models
);


