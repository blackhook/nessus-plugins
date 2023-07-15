#TRUSTED ad3a02a5a6d2ba8efd4ff37fe7537b0afa2171ed698604745474668613aeb9a0308701ae4275c68eaa7c6c38b784acffe5463e13a3163563dc4522ea7ea0d50b07b30db244e11a5c2408ed7262dcdcdd9169e53ec0a59b77f140619f4bcf180965c3304dc4b1e6b521ababf6037ace129fcd6e89a3af6f92b22492908119c6bd6b4890aced40cee95e5ab7f4f6f7423e551e706b89a0b8af67dcba1297879fd894db97613fee65a65269be277316335637216f176e4d303f5a624cc85e1e55ace4be5b8d0fa35f01ec1d363f8da9ccd7695ca3b8175400301012d1652320cd8dc40221d8596c84ae80b9efaac8df2b5cf74711f17ae41a397beea4e05199dafcb76390ffbcc95345db652e4bf64525b5c4d7bf858e5512b09f00e4d917651c903c5b905e73d2a5a30368b0d3b495c5615d49ee8eafb9e0b39ffa90dcd415e7d46656f5bb4e9bd00e7e7cea4bdf21b06e44da25c86a293d30a214d4dc5eb37af85fbb75a8666e357fbc91a23e79769d2ff18fd5cd7050f5741218a2da83505aa9bd364b32596f150a94271adbcf95332d8a3969a1f3f3f2e4edb1125acc2071603512a869565931d71bb409c184a3e6d95df6060a6e5eaeda50f15f11c4e151250d4363aef3fcb64be74bd7df536a2cc6f44a1868ee802f2c111d541542bce4962ae85029fb0a205eab014cbcc3680493d4e24c09fb04c8bc12142bcbd651fc63
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(139792);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2020-3532");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt01179");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu30682");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu30689");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cucm-cuc-imp-xss-XtpzfM5e");
  script_xref(name:"IAVA", value:"2020-A-0297-S");

  script_name(english:"Cisco Unified Communications Manager XSS (cisco-sa-cucm-cuc-imp-xss-XtpzfM5e)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Unified Communications Manager is affected by a cross-site scripting 
(XSS) vulnerability in its web interface component due to improper validation of user-supplied input before returning 
it to users. An unauthenticated, remote attacker can exploit this, by convincing a user to click a specially crafted 
URL, to execute arbitrary script code in a user's browser session.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cucm-cuc-imp-xss-XtpzfM5e
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b594d314");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt01179");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu30682");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu30689");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco Security Advisory cisco-sa-cucm-cuc-imp-xss-XtpzfM5e");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3532");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ucm_detect.nbin");
  script_require_keys("Host/Cisco/CUCM/Version", "Host/Cisco/CUCM/Version_Display");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco Unified Communications Manager');

# Neither advisory or BIDs state any fix version.
# BIDs simply say: No release planned to fix this bug
# Range is 0 to next release after highest vuln version in an attempt to flag for all current versions.
vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver' : '12.5.1.13900.152'}
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['display_version'],
  'bug_id'   , 'CSCvt01179, CSCvu30682, CSCvu30689',
  'disable_caveat', TRUE,
  'fix', 'No known fix, refer to Cisco advisory'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);

