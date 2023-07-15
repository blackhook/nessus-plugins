#TRUSTED 2ea16f3cbdfe6a75e934f41d27b3a41347156bbf00f5f9d99f1e524163c1cd7e6a3aafec4a5da81a573f15c49647681f1ffdb457b29f6139ad42e6511c94f159d4b5904f9a66abfa042bea368514320924c22946893a3462fa99064327dee59a61fa81eb0c759235a50551f023befe34abc9dff06041bfffe30dc655468a9054ccc76b9caabd6175d770e032a1f118366664866b80529e3dd6b14de08813fa03642c168567daada1be0e7984010864d994c6434b96adbc18a5a77bcc835a8e70209c1d2605eb418797a0ffbf5fbdd9dcb6587bf57ec2fd43e547b8d5070485f07e1441b889c94f2c7da28718504c0d7fed2248525273e2e57f64188db4a6bd5ed5ef52c5d7d813c70539ce9df682e6591b16b6796ca8777808e92f4b7516d86fd4568c8169806829a2205b022d979600caf2f75491dada224a1a881ac91a4b72c1b8193543b375f60efabe2235c9f88e713ee06ea4bd304791cf8d45612126bbb0f9be03bd22f180d17ba93ab3b9f986fadc58747c7fa19b45a982420d73f67854314cefe301b3ec9cdc50dfedbc5daa985ae1ff08302566165155d3668be453258c1f4158a377d03980136593b36fe0bcf36b699220ad8977d4a42cdbfaaf17c9bebb7db520ac01f4f93bfd042df9635735e4585988f8a601a6e801cedafe96ce757992933c52e02fcf8562f6c5ba25929f01d097ce32f45fd573c8c101cf2e
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126102);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/06");

  script_cve_id("CVE-2019-1673");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvn64652");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190206-ise-xss");

  script_name(english:"Cisco Identity Services Engine Cross-Site Scripting Vulnerability (cisco-sa-20190206-ise-xss)");
  script_summary(english:"Checks the Cisco Identity Services Engine Software version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Identity Services Engine
Software is affected by a cross-site scripting vulnerability.
This could allow an authenticated, remote attacker to conduct a
cross-site scripting (XSS) attack against a user of the web-based
management interface.The vulnerability is due to insufficient
validation of user-supplied input that is processed by the web-based
interface. An attacker could exploit this vulnerability by persuading
a user of the interface to click a crafted link. A successful exploit
could allow the attacker to execute arbitrary script code in the
context of the interface or access sensitive browser-based
information.

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190206-ise-xss
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9e3cd932");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvn64652");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs
CSCvn64652.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1673");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/21");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ise_detect.nbin");
  script_require_keys("Host/Cisco/ISE/version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco Identity Services Engine Software");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

vuln_ranges = [
  { 'min_ver' : '2.1.0', 'fix_ver' : '2.2.0.470' },
  { 'min_ver' : '2.4.0', 'fix_ver' : '2.4.0.357' },
  { 'min_ver' : '2.5.0', 'fix_ver' : '2.6.0.156' }
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

# ISE version doesn't change when patches are installed, so even if
# they are on the proper version we have to double check patch level
required_patch = '';
if      (product_info['version'] =~ "^2\.2\.0($|[^0-9])") required_patch = '14';
else if (product_info['version'] =~ "^2\.4\.0($|[^0-9])") required_patch = '8';

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_NOTE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvn64652',
  'fix'      , 'See advisory',
  'xss'      , TRUE
);

# uses required_patch parameters set by above version ranges
cisco::check_and_report(product_info:product_info, reporting:reporting, workarounds:workarounds, workaround_params:workaround_params, vuln_ranges:vuln_ranges, required_patch:required_patch);
