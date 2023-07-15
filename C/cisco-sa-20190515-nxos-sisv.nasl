#TRUSTED 591f4c31f13e802ae850a209e418cc1c90197f7c1f6ac029d4cdef51bbe1db4f472485e7abf7a3e330631fb587a638ecec122c7579e80405af666b8d3cbf7c4e289615fd25d8daecd4d9c1a0ccfa69f946c93fd63d5afc52abe1457436af8c4c4ac276dc4fc7b0d409bf0aff4ebb505a66747662026403f87df6c280db1e470f4b3db4c41f0a432e38c9ba541ddf6a826f159413404be45dfc20b1e1c7630a8ba22f94bd1136b9fda6e74c680716b543e9f4309069301666bcd26cba2aa7dfec31b56b42671173ad3a708416a0ad619e8302c1b820589c62b572820616b969baeabd6dc18ba4db977f74d4e187aac05c96dca0216fddf2186491f4d834bdcdbc6423460878a58782b839c9be4d5cfe6e3ad2e920ae92502e439cd56bf36b9c34db3a4917796541048e7475012c7a3ccbaa01ca862f2b38c2963e6f69ef22c677137c1b806a95a9a7fe4d0e8ed7f63d55533c7b2ef4db8e7bf10a4813cbf3e19575e353b860db78e2c20e52534caf238f1c2b29c032b0ee915a542b70dcb31b7b0d51f5fb02ccd92e848a50ebd7c686122ef96694d23b668c84c74df13ea17496f559f4944acb788856733a156519b2d10d8981e5245365ca483878b9cfdf87fe281ef02680bedb60e059e2b481c1f3d70f85f065f330f1621266f943c6bd7e3d27b14260a86f8060e590a5ef2017f530bff8636485b726d9f5f38d6d2ce1f693
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125778);
  script_version("1.6");
  script_cvs_date("Date: 2019/12/20");

  script_cve_id("CVE-2019-1810");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj14078");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190515-nxos-sisv");
  script_xref(name:"IAVA", value:"2019-A-0180");

  script_name(english:"Cisco Nexus 3000 Series and 9000 Series Switches in NX-OS Mode CLI Command Software Image Signature Verification Vulnerability");
  script_summary(english:"Checks the version of Cisco NX-OS Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software isa ffected by a vulnerability in the Image Signature
Verification feature used in an NX-OS CLI command in Cisco Nexus 3000 Series and 9000 Series Switches could allow an
authenticated, local attacker with administrator-level credentials to install a malicious software image on an affected
device.The vulnerability exists because software digital signatures are not properly verified during CLI command
execution. An attacker could exploit this vulnerability to install an unsigned software image on an affected device.
Note: If the device has not been patched for the vulnerability previously disclosed in the Cisco Security Advisory
cisco-sa-20190306-nxos-sig-verif, a successful exploit could allow the attacker to boot a malicious software image.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190515-nxos-sisv
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d5b1dda9");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190306-nxos-sig-verif
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bf14d312");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj14078");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvj14078");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1810");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(347);


  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('global_settings.inc');
include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

if ( product_info.device != 'Nexus' ||
   ( product_info.model !~ '^[39]0[0-9][0-9]'))
  audit(AUDIT_HOST_NOT, 'affected');

# Currently no method for checking the Product IDs
if (report_paranoia < 2) audit(AUDIT_PARANOID);

version_list=make_list(
  '9.2(1)',
  '7.0(3)I7(5a)',
  '7.0(3)I7(4)',
  '7.0(3)I7(3)',
  '7.0(3)I7(2)',
  '7.0(3)I7(1)',
  '7.0(3)I6(2)',
  '7.0(3)I6(1)',
  '7.0(3)I5(2)',
  '7.0(3)I5(1)',
  '7.0(3)I4(8z)',
  '7.0(3)I4(8b)',
  '7.0(3)I4(8a)',
  '7.0(3)I4(8)',
  '7.0(3)I4(7)',
  '7.0(3)I4(6)',
  '7.0(3)I4(5)',
  '7.0(3)I4(4)',
  '7.0(3)I4(3)',
  '7.0(3)I4(2)',
  '7.0(3)I4(1)',
  '7.0(3)I3(1)',
  '7.0(3)I2(5)',
  '7.0(3)I2(4)',
  '7.0(3)I2(3)',
  '7.0(3)I2(2e)',
  '7.0(3)I2(2d)',
  '7.0(3)I2(2c)',
  '7.0(3)I2(2b)',
  '7.0(3)I2(2a)',
  '7.0(3)I2(2)',
  '7.0(3)I2(1a)',
  '7.0(3)I2(1)',
  '7.0(3)I1(3b)',
  '7.0(3)I1(3a)',
  '7.0(3)I1(3)',
  '7.0(3)I1(2)',
  '7.0(3)I1(1b)',
  '7.0(3)I1(1a)',
  '7.0(3)I1(1)',
  '7.0(3)F3(5)',
  '7.0(3)F3(4)',
  '7.0(3)F3(3c)',
  '7.0(3)F3(3b)',
  '7.0(3)F3(3a)',
  '7.0(3)F3(3)',
  '7.0(3)F3(2)',
  '7.0(3)F3(1)',
  '7.0(3)F2(2)',
  '7.0(3)F2(1)',
  '7.0(3)F1(1)',
  '7.0(3)',
  '7.0(2)N1(1a)',
  '7.0(2)N1(1)',
  '7.0(2)I2(2c)',
  '7.0(1)N1(3)',
  '7.0(1)N1(1)',
  '7.0(0)N1(1)',
  '6.2(9c)',
  '6.2(9b)',
  '6.2(9a)',
  '6.2(9)',
  '6.2(8b)',
  '6.2(8a)',
  '6.2(8)',
  '6.2(7)',
  '6.2(6b)',
  '6.2(6a)',
  '6.2(6)',
  '6.2(5b)',
  '6.2(5a)',
  '6.2(5)',
  '6.2(3)',
  '6.2(2a)',
  '6.2(25)',
  '6.2(23)',
  '6.2(21)',
  '6.2(20a)',
  '6.2(20)',
  '6.2(2)',
  '6.2(19)',
  '6.2(18)',
  '6.2(17)',
  '6.2(16)',
  '6.2(15)',
  '6.2(14b)',
  '6.2(14a)',
  '6.2(14)',
  '6.2(13b)',
  '6.2(13a)',
  '6.2(13)',
  '6.2(12)',
  '6.2(11e)',
  '6.2(11d)',
  '6.2(11c)',
  '6.2(11b)',
  '6.2(11)',
  '6.2(10)',
  '6.2(1)',
  '6.1(5a)',
  '6.1(5)',
  '6.1(4a)',
  '6.1(4)',
  '6.1(3)S6',
  '6.1(3)S5',
  '6.1(3)',
  '6.1(2)I3(5b)',
  '6.1(2)I3(5a)',
  '6.1(2)I3(5)',
  '6.1(2)I3(4e)',
  '6.1(2)I3(4d)',
  '6.1(2)I3(4c)',
  '6.1(2)I3(4b)',
  '6.1(2)I3(4a)',
  '6.1(2)I3(4)',
  '6.1(2)I3(3b)',
  '6.1(2)I3(3a)',
  '6.1(2)I3(3.78)',
  '6.1(2)I3(3)',
  '6.1(2)I3(2)',
  '6.1(2)I3(1)',
  '6.1(2)I2(3)',
  '6.1(2)I2(2b)',
  '6.1(2)I2(2a)',
  '6.1(2)I2(2)',
  '6.1(2)I2(1)',
  '6.1(2)I1(3)',
  '6.1(2)I1(2)',
  '6.1(2)I1(1)',
  '6.1(2)',
  '6.1(1)'
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
'port'     , 0,
'severity' , SECURITY_WARNING,
'version'  , product_info['version'],
'bug_id'   , 'CSCvj14078'
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list, switch_only:TRUE);
