#TRUSTED 4e49409bf5c57bee360ab5ce693e929bb2aa960bec97396bc358768334ec756f23306adc0c10cec9751da5acd77fc57b88cfb77b47403f8b9e58a2723ebec5bea41156601f9bda4416a785feec14a5cc8c4452e92e688b8571b2ae68d386a03c54e08280cb75ab3f9c9d18b06d7f977ee5c488f567cbbf26a0b13c4993b134b503217de022eca657b7720a3fb3272c5adbfc3d2d1fae89b34022c993a36200945a7bf27f3aac907f3dbe4dafb719f7af6aef142b149fe47037137238f1bdf19029055e65cbd1f0a0d12a1c2a7923e9c97f83d72ae104fc5ea11b12730627cb30b29d7ce47f94bf7c1f3f1ca3a14a6bdc7b20bc990606b4666e9a574479bf34bba5ba68ebfcf8463121f65db0e6b31ae30324d6d58751d2b479c474be5cff317acf1508ec0ddacc326bf6b7ef0ab745e387d064aa80ac13eb2ba4bce40001c3ca8a556d1982437853fa818f7b148ed52bd31ba874cdf7fbb7b371881165b63ec84094a1c9ebdc6633ba6ff0b7d05377b94e4ba0e32570fcb8fb35906bc5d7fd5307d4ab527968d8ede89f713efdca122d8989b32890c9e421c088c47d413807f7911e4733197ee1c1221c5f7b4802644547fe50c6826b38a9d05e764f02d755235f38f19d24831a756421de2a9a4ce625e80037a8728cf568a70ce07777d3255cd5393bb145953d42d9a404b8e4cf64b13559b9dde22c1b290ee3e2838d0c323d
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106400);
  script_version("1.7");
  script_cvs_date("Date: 2019/12/20");

  script_cve_id("CVE-2018-0095");
  script_bugtraq_id(102729);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvb34303");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvb35726");
  script_xref(name:"CISCO-SA", value:"cisco-sa-2018117-esasma");

  script_name(english:"Cisco Email Security Appliance Privilege Escalation Vulnerability");
  script_summary(english:"Checks the Cisco Email Security Appliance (ESA) version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Email Security
Appliance (ESA) is affected by a privilege escalation vulnerability.
Please see the included Cisco BIDs and the Cisco Security Advisory 
for more information.");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:email_security_appliance_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_esa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Email Security Appliance/Version");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco Email Security Appliance (ESA)");

vuln_list = [
  {'min_ver' : '1.0.0.0',  'fix_ver' : '9.8.0.092'},
  {'min_ver' : '10.0.0.0', 'fix_ver' : '10.0.1.087'}
];

if(product_info['version'] =~ "^[0-9]\.") fixed='9.8.0-092';
else fixed='10.0.1-087';

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version', product_info['display_version'],
  'fix', fixed
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_ranges:vuln_list);
