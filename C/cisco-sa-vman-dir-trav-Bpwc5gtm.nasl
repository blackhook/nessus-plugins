#TRUSTED 71c4bb8be6fb9ee03a9f36d2c3a249c504c410167ff58737197f70bc59d04b62d63751b0e2d063eeada2b9dade3283982febe6d920803c6634b882457db89b291773c178e79be53aabc0486a7c42d933c4156c82601af6acbfbdceab1084a3fd3cc82bec6e4dabf86f832d1844ad2868e2ff929fd2f9cbdbaba10d684fc575de1df3265d671deb91ec3522da20c177f1cd30b6d67df14ead6b1bc0f4b5701d25cbe73ae8debed4cfd79f31e250fbbdc28d9f67bbc8b957448745f74b1d2254c2d2f03ed9728cea062c456bd0bca3da7e313e174dfaefe4d9bda00e003f0fe5159a81046a07cc14168e739a9e218eb8e4ae5ae383d22d1963ae54d88b46daab76ff4e040a36a0e40ab55c133d7252946e6c117ff22a21282b5f141abae149fe844ac4a3ab524ad553f0b4069b2d6bc6a5374a93d811ebc78d9aa8661f235d39976fca417806db8d7c7c3749d6f6283dd240b98b3a4503b976b91bc9225d917eaee1515e2561b40188181dcd00ed54147adaf2058ff1980c29a8575bd48aa418e59141f303b10a199e03f8784f8a44df1f03e90b95b583b2eca863c7fa90e67426bda9277041be8cf1fb16e38204ac0326d1d8f174039a3b2bdcb608b887c731bdb6ffc00d47bc8d5d5fae7a03d3ef45c08e8138ee99927945afa9facbb9ede525c131b4f277459e23a51dffeac069fcb30398675be17067cd511bdc78cb68b639
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(149880);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/26");

  script_cve_id("CVE-2021-1465");
  script_xref(name:"IAVA", value:"2021-A-0118");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu28396");
  script_xref(name:"CISCO-SA", value:"cisco-sa-vman-dir-trav-Bpwc5gtm");

  script_name(english:"Cisco SD-WAN vManage Directory Traversal (cisco-sa-vman-dir-trav-Bpwc5gtm)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN vManage is affected by a directory traversal vulnerability due to
insufficient validation of HTTP requests. An authenticated, remote attacker can exploit this by sending crafted HTTP
requests in order to obtain read access to sensitive files. Please see the included Cisco BIDs and Cisco Security
Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-vman-dir-trav-Bpwc5gtm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d7392e8f");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu28396");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu28396");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1465");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"stig_severity", value:"II");
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
  { 'min_ver' : '0.0', 'fix_ver' : '18.4.6' },
  { 'min_ver' : '19.2', 'fix_ver' : '19.2.4' },
  { 'min_ver' : '20.1', 'fix_ver' : '20.1.2' },
  { 'min_ver' : '20.3', 'fix_ver' : '20.3.2' },
  { 'min_ver' : '20.4', 'fix_ver' : '20.4.1' }
];

var version_list = make_list(
  '18.4.302.0',
  '18.4.303.0',
  '19.2.097',
  '19.2.099',
  '19.2.31.0',
  '20.1.12.0'
);

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvu28396',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list,
  vuln_ranges:vuln_ranges
);
