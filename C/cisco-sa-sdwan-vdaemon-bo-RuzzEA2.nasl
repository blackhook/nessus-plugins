#TRUSTED 5959d6236d535cd98d3808a75faa50974aeab10e2ed4d0776228c6b5fc3b41d511b2d69f138943471e5a2e291d451b2f4944664f00189fef8cb9654e1b715b2f2872dddf1900094a95264e88f59cfe37138e4f33769d949755675affcb69360fcae3b1bcd12ff5537e5d4d68a9caeaa23d6d99d51eb2050a529a1cc4914421461b9d111fec0cc30f203eb41ad637a30b375b7f430c63feade22b5611d1ca0c040e8ba364b0e196d7fc527ea9dcbe8c91fed8c7750c3475e98207b17d77e91b5e8b8219718f7d9d27f9cbf46dfffe3235475cba258e307dd8adaa7442be15a9726e6ba78674b79304607dea832a083e92a55f9cd501043441034857ad220c6a71f7071305eccc4b30fd846d0b3fe28834e0c4844062fb8583c0e8834ffd14b54290d6c1f2be835cf557715fba0ce45bd02087fa649e4c96e1b3670191e774d69fac94e2bb22b06dbfa72cc03ead4f6714f998379df38b41980b5a0ff0b4c495c4453d0b3cfaf5723460e4ca96a350536e1f345036197c384bbaaad244a822169bf5aa970088aff5472df9b3569e471f0873563ab691939679ac01773e82bb29637c44ecf1d6948e957f076c207942dc3ebba987042a4829cb1277ef333bea41a01759df21af1b1cd718c5570dd6475373832db37116a3059e5ede6f0ae16318674d175649ab70768625af9062698933fe39bd126b9be41d9150ff923aee059414
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(149879);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/26");

  script_cve_id("CVE-2021-1466");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt11526");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sdwan-vdaemon-bo-RuzzEA2");

  script_name(english:"Cisco SD-WAN vDaemon Buffer Overflow (cisco-sa-sdwan-vdaemon-bo-RuzzEA2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN vManage Software is affected by a buffer overflow vulnerability
due to incomplete bounds checks for vDaemon service data. An authenticated, local attacker can exploit this, by sending
malicious data, in order to cause a denial of service (DoS) condition.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-vdaemon-bo-RuzzEA2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b60e7466");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt11526");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvt11526");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1466");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Viptela');

if (tolower(product_info['model']) !~ "vmanage")
  audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '18.4.5' },
  { 'min_ver' : '19.2', 'fix_ver' : '19.2.3' },
  { 'min_ver' : '20.1', 'fix_ver' : '20.1.1.2' },
  { 'min_ver' : '20.3', 'fix_ver' : '20.3.1' },
  { 'min_ver' : '20.4', 'fix_ver' : '20.4.1' }
];

var version_list=make_list(
  '18.4.302.0',
  '18.4.303.0',
  '19.2.097',
  '19.2.099'
);
 
var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvt11526',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  vuln_versions:version_list,
  reporting:reporting
);
