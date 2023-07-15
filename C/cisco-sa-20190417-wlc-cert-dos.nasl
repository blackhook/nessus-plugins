#TRUSTED 35bc3a7bbbf942f316f6689dd4b2efdbc2f62a041d234c467747eb4b8ed5aca09d5cfaaf194a94a5cee3db05b3be652678d053d49a8e093876d3a279778895d28af5eb7350b91917216fcf035bf8730e57c9efae66b93257f21bdc6b8edb8c80ccbb96ef4b8962532a94697fbfe55568b3d1275d9d4bd1bb7da7777594527d9e130d5221249b1df9cf06bccf4d3b46ce80dceb2798d19820c95bfeecaeb28f61e6915760820d993ac59ba75526b382d947049fbf5e66ecc113f8dd2ba35580a41b0dad9ba16376c26afb026bb184ae6c5597b6cd9d60e4bc9ec642e33d0d6704c789786011786cab70969bee8ce1076db8bfe76c9a1a7070494de498ac7dbfa3bc47488b5e5baa2031cdf769af4504f11a664695a09c08fd8b90fd40590038e849c71ce0ec230e08e9f1c5a19815f48f84bd294f2574efc5354fcd25224f8bcdd6c10d913a164379bf8c3a754aadbf8eab92a306d9dfd719e1f60f3509fa05f1d4e54ee6422bb301a808d4bb1d3b440e0fc2cd6ba279e743a12f73095d054d3005bfe9ef8929432790329c807ede4bff920bc1b8d89a6905b4008b517bafe21d46c03c5537d084d25b80cbb4da4e8350d1f1853310030e6214a71db16e574643d6412ee5c5316b6f7f16700a01f02247c7927fc5a62413a52b34907149145c03f13ffa938d1aaf44eb00435b4bfc8ac2e24a3d644552342e3bb53851f16542f8
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124334);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/20");

  script_cve_id("CVE-2019-1830");
  script_bugtraq_id(108028);
  script_xref(name:"CWE", value:"CWE-20");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj07995");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190417-wlc-cert-dos");
  script_xref(name:"IAVA", value:"2019-A-0132");

  script_name(english:"Cisco Wireless LAN Controller Locally Significant Certificate Denial of Service Vulnerability");
  script_summary(english:"Checks the version of Cisco Wireless LAN Controller (WLC)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Wireless LAN Controller
(WLC) is affected by following vulnerability

  - A vulnerability in Locally Significant Certificate (LSC)
    management for the Cisco Wireless LAN Controller (WLC)
    could allow an authenticated, remote attacker to cause
    the device to unexpectedly restart, which causes a
    denial of service (DoS) condition. The attacker would
    need to have valid administrator credentials.The
    vulnerability is due to incorrect input validation of
    the HTTP URL used to establish a connection to the LSC
    Certificate Authority (CA). An attacker could exploit
    this vulnerability by authenticating to the targeted
    device and configuring a LSC certificate. An exploit
    could allow the attacker to cause a DoS condition due to
    an unexpected restart of the device. (CVE-2019-1830)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190417-wlc-cert-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6ef69a18");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj07995");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvj07995");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1830");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:wireless_lan_controller_(wlc)");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wlc_version.nasl");
  script_require_keys("Host/Cisco/WLC/Version", "Host/Cisco/WLC/Port");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Wireless LAN Controller (WLC)');

vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '8.3.150.0' },
  { 'min_ver' : '8.4', 'fix_ver' : '8.5.140.0' },
  { 'min_ver' : '8.6', 'fix_ver' : '8.8.100.0' }
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
'port'     , product_info['port'],
'severity' , SECURITY_WARNING,
'version'  , product_info['version'],
'bug_id'   , 'CSCvj07995'
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_ranges:vuln_ranges);
