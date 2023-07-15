#TRUSTED 3289798919aa372b4e33c2f2a03c4ef677985cf16b8cffd386e8eef7000b6835d78a4659f061e7c4667658cb220047cd0c4d4325ce0beb8a3156fe52b01e37c6c2e50e48df0ad350fbe706113a602bed60598bb1965e09057d578ec06d4be30d05b7ce6bf0e2a79b0773d03208e0ea70e7f736d4090832f30ff6523b254607e2b8fc390b6fbe08437a7e2a058cc2da0acc9539e59728aa8740f7cbedda33cdacf25f59fdb28485b82dc159f36eb050e288936204a0f1dc8ba4b372de1b35365e5bb613262d453e8ef264b0730ec98ad4d0af5195489344abf785a7d8ab6f999c25de274c4fd43fe4fa369ff6ce08d286a497dc9c140ae9644fd37ce594f09c6ab5fe30e65152b76ab1829dde5d34d9f94479e7a0e8fd76337781f2df742a94c9a62fb16cfa10eacc3f7fbb4d81487188c4df679ea77e535353fcd432900be69491c45c2b0ab22c3885b8c716403c75d07c2b24b1523b060d6cd9c9000813d324f1bcaccada4d5ae96c3a9b51dab2230de7f7de5e684905aae70b59f6cba3e00a0f5c317f55f2135ca7b161fdcb134292e85ef1a926fbeedd3cbbebe9afaadc7ca4ecbb814f3899cd779e01825b478bfa17abda01e64a8ebe25c85d84d1f525046471d14c3cc38f1648a635974a98e612a791445d21cae636692befe54f8c71919ca7b73124f0a53236c19a1398881227371db6c404dd44ab249cdbc4b42564d0
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106401);
  script_version("1.7");
  script_cvs_date("Date: 2019/12/20");

  script_cve_id("CVE-2018-0095");
  script_bugtraq_id(102729);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvb34303");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvb35726");
  script_xref(name:"CISCO-SA", value:"cisco-sa-2018117-esasma");

  script_name(english:"Cisco Content Security Management Appliance Privilege Escalation Vulnerability");
  script_summary(english:"Checks the Cisco Content Security Management Appliance (SMA) version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Content
Security Management Appliance (SMA) is affected by a privilege
escalation vulnerability. Please see the included Cisco BIDs
and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180117-esasma
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?040af8d4");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvb34303");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvb35726");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco Security Advisory
cisco-sa-20180117-esasma.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0095");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/26");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:content_security_management_appliance");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_sma_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Content Security Management Appliance/DisplayVersion", "Host/AsyncOS/Cisco Content Security Management Appliance/Version");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco Content Security Management Appliance (SMA)");

vuln_list = [
  {'min_ver' : '1.0.0.0',  'fix_ver' : '11.0.0.115'}
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();


reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['display_version'],
  'fix'   , '11.0.0-115'
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_ranges:vuln_list);
