#TRUSTED 6733d632429cff88f086817e92ed39d58693549481ae51018467a38a2e4a6132316c3dd173f87ce17e96b019a7f11f31c30270d466036034d3483bb9644bb8c952b33d7917ec70e5376940733858704e9baa64547f790a148e12849b02bd5fdc5165025085ab803be7efe58d6c6859ab404249ecf07c17dda275920cc7c11688b935b4a1e98217c9299deb511ff959e24d65551a60d1a7748b956c7a1938d2eea50f6d23d7401825df77794469d739e2dc72e6c5e041ebdb31f01eb41e34b2c38a0b77e8342b695a1f1a420413eec4e04ac23de8e0ceb413d1803747bbee1d25c6e1399a81301a163361ec92c57a9805dff78cf8c6ac5ac1325aef0c9d337d73d513c03f71cb344f42fd49fdee75f24b8288a60698ee4df88e5a1c3c926520189628544effea55b8432f6859da86353f954969f26b35f1ba8dbd8d8032e04fab81d9a87a2b4f7c9d6c10cc4a680c66139e852a5b7353130a4802b624a621135e31029c823146c7e17a6428ab7c929c3ad3015920820838e913a22ae3c70094ec49f227f1361b07bc39372f1cf27e18ddc1720722ecb7800310f521f3be85ef66eea76de1a2b01a84687f67086a2d21256a4f02250a8a361baa67b9f1e4709738c0a3694aa1215cd1d59e34b42d4bf0222e4d9ceae5186d1f15d2e1de01f9ba85d9f8a3f180c2173e3fbb89cc7e3d0a173479e5f8009558b00e09b09c55c82e20
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(130368);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2019-15272");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp14434");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191002-ucm-secbypass");
  script_xref(name:"IAVA", value:"2019-A-0362");

  script_name(english:"Cisco Unified Communications Manager Security Bypass Vulnerability (cisco-sa-20191002-ucm-secbypass)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Unified Communications Manager is affected by a vulnerability that allows
an unauthenticated, remote attacker to bypass security restrictions. This is due to improper handling of malformed HTTP
methods. An attacker can exploit this vulnerability by sending a crafted HTTP request in order to gain unauthorized
access to the affected system.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20191002-ucm-secbypass
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?939903a5");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp14434");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvp14434");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-15272");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/30");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ucm_detect.nbin");
  script_require_keys("Host/Cisco/CUCM/Version", "Host/Cisco/CUCM/Version_Display");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Unified Communications Manager');

vuln_ranges = [
  # 10.5(2)SU9 https://www.cisco.com/web/software/282074295/147607/cucm-readme-1052su9.pdf
  {'min_ver' : '0.0',  'fix_ver' : '10.5.2.21900.13'},
  # 11.5(1)SU6 https://www.cisco.com/web/software/282074295/145230/cucm-readme-1151su6.pdf
  {'min_ver' : '11.5', 'fix_ver' : '11.5.1.16900.16'},
  # 12.0(1)SU3 https://www.cisco.com/web/software/286319236/146004/cucm-readme-1201su3.pdf
  {'min_ver' : '12.0', 'fix_ver' : '12.0.1.23900.9'},
  # 12.5(1)SU1 https://www.cisco.com/web/software/286319236/146815/cucm-readme-1251su1-Rev3.pdf
  {'min_ver' : '12.5', 'fix_ver' : '12.5.1.11900.146'}
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['display_version'],
  'bug_id'   , 'CSCvp14434',
  'disable_caveat', TRUE
);

cisco::check_and_report(product_info:product_info, reporting:reporting, vuln_ranges:vuln_ranges);
