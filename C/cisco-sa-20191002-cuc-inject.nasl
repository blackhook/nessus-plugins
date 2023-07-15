#TRUSTED 8b0a4baf48cde9fd4f33b5ba27ee6d1c631d6a1fe402334d5ff418d633abc2e1dc83d8071f622de88439d6f299ae0e0bb4d62479aea2b8f73ec0e7c9116fd822b4d8b1b928b10623f20d690e5f07e73bec067927696af05723a868787e5beee738032dded9a9ab06dd2ba512a430f2bca02bd7c4c8cdc8e7a7691109e74a94932ae49007fa208646ea2d4f0a8d9c11fbc5578dc22ab6f7333ee92a535a79212daf019cb725c20c2bc948fffd2bab6c9e061ddc678db7abcf5e59a232ae42488272b36678211c7e293fe1163971b2e052b42ced01da9cc01543a304e11101282ebe6a3ddb8c7de1b6dfe77a635a7992c35981e58b31ae91fa9b6e1a8986c168dcf43e2152cf3bdb43124b881dad8ed8cf5c15ce9e4daf7d49ecf8f4552414c36154c68a11ad90eec0d2465e30c22acafeb36eba16bd7139b00215d31f6cc749e26f59b3b5fcf68b37cf95abcff0cb831faadb660985905d08e375b4dfe99fe6bbbf46ce3c95cca0e180c0b78401ffe28dcf3f289171f741e3b09e0485d03ba0d439e3507557de3fa07c51fdf824dbe1d0d38b1515583157117fc224cb966917a66b6b632eedeabf4cf396baede846cb012c22a118d952c11e51b85a348feab284186388e4548ff94518de0793fbca48536491a634934d5b3e7dfc686b5b5ef43ae04d9bf3d57b252319da23d1061d6a40a6a5624513598978da8efa2bfa25bb5b
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(130367);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2019-12710");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo42378");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191002-cuc-inject");
  script_xref(name:"IAVA", value:"2019-A-0362");

  script_name(english:"Cisco Unified Communications Manager SQLi (cisco-sa-20191002-cuc-inject)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Unified Communications Manager is affected by an SQL injection
vulnerability. This is due to improper validation of user-supplied input. An authenticated, remote attacker can exploit
this by sending crafted requests with malicious SQL statements to determine the presence of certain values in the
database, impacting the confidentiality of the system.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20191002-cuc-inject
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?239834a9");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo42378");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvo42378");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12710");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(89);

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

product_info = cisco::get_product_info(name:"Cisco Unified Communications Manager");

vuln_ranges = [
  // 10.5(2)SU9 https://www.cisco.com/web/software/282074295/147607/1052su9cucrm.pdf
  {'min_ver' : '0.0',  'fix_ver' : '10.5.2.21900.13'},
  // 11.5(1)SU6 https://www.cisco.com/web/software/282074295/145230/b_1151su6cucrn.pdf
  {'min_ver' : '11.5', 'fix_ver' : '11.5.1.16900.16'},
  // 12.0(1)SU3 https://www.cisco.com/web/software/286319533/146387/b_1201su3cucrn.pdf
  {'min_ver' : '12.0', 'fix_ver' : '12.0.1.23900.7'},
  // 12.5(1)SU1 https://www.cisco.com/web/software/286319533/146820/b_1251SU1cucrn_rev1.pdf
  {'min_ver' : '12.5', 'fix_ver' : '12.5.1.11900.57'}
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['display_version'],
  'bug_id'   , 'CSCvo42378',
  'disable_caveat', TRUE);

cisco::check_and_report(product_info:product_info, reporting:reporting, vuln_ranges:vuln_ranges);
