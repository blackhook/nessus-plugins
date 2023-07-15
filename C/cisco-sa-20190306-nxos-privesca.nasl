#TRUSTED 15f5c79e009063f4e267b5d6e9aafc01a84ba46adce8fdd5940279fa2bed12eb6176cd17b588bf099868d41a6c5d4fa5e1bdf90e8ae7ce783dff3378560146481298a302924c2c9efb8e616aad64c8da3c6f97e79140d6be70619a52cea780d22e440cff4361d85ac6af9a49129d049c12577ac12cf9feffd713e640abd614214e9a9bb3666af188e3893f5e76dfa5359d154cf2fbf34eec5c77b1e11a559ef2218d49c3823b8d93375762fd428f98b1515320347b2b381ff811707766c7627c660e36c00fe6e548768b7ca8998d7adf12ec082e4009f133173a90d34b3438fb4f0fe69a3de51d5be4a844065a33b0f48635251202bc566dbe741e0fb8c15fe9b2bdca6c04df6200076dca71f1028cf6eb749f885f73d53553bcbad30d68ca830ea791d0798dfe704131bbcc7407b201bbeba5bd33300ae332415be0a363af62fb3481c87989ccce1c07d7e0af43712f4e6c680862a00359a08cef347788bd8f28ed1f261d602cbe9d568d0b2133585b192680a6107660380cec61174519e0571128bd9eaa22e2cdf0ee84944813ab44e0c291d149662f5a21c331f43822baa7f148deb29f2560e45e9fecf639db2eae7e480d8987e13552c95285e58845e91e93d92a78d9b9ad9ec86988d9115e56e9f908b4e9d12028e8d7d11d56210178fede4d8be24568ec81d947fcffe9caf4171150458bce7bf375451832c4112c6eaf
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(132100);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/27");

  script_cve_id("CVE-2019-1604");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi53896");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190306-nxos-privesca");

  script_name(english:"Cisco NX-OS Software Privilege Escalation Vulnerability");
  script_summary(english:"Checks the version of Cisco NX-OS Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is
affected by following vulnerability

  - A vulnerability in the user account management interface
    of Cisco NX-OS Software could allow an authenticated,
    local attacker to gain elevated privileges on an
    affected device.The vulnerability is due to an incorrect
    authorization check of user accounts and their
    associated Group ID (GID). An attacker could exploit
    this vulnerability by taking advantage of a logic error
    that will permit the use of higher privileged commands
    than what is necessarily assigned. A successful exploit
    could allow an attacker to execute commands with
    elevated privileges on the underlying Linux shell of an
    affected device. (CVE-2019-1604)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190306-nxos-privesca
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2494752e");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-70757");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi53896");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvi53896");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1604");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(285);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/18");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco NX-OS Software");

switch (product_info)
{
  case product_info.model =~ "30[0-9][0-9]":
    version_list=make_list(
      "7.0(3)I7(4)",
      "7.0(3)I7(3)",
      "7.0(3)I7(2)",
      "7.0(3)I7(1)",
      "7.0(3)I6(2)",
      "7.0(3)I6(1)",
      "7.0(3)I5(2)",
      "7.0(3)I5(1)",
      "7.0(3)I4(8z)",
      "7.0(3)I4(8b)",
      "7.0(3)I4(8a)",
      "7.0(3)I4(8)",
      "7.0(3)I4(7)",
      "7.0(3)I4(6)",
      "7.0(3)I4(5)",
      "7.0(3)I4(4)",
      "7.0(3)I4(3)",
      "7.0(3)I4(2)",
      "7.0(3)I4(1)",
      "7.0(3)I3(1)",
      "7.0(3)I2(5)",
      "7.0(3)I2(4)",
      "7.0(3)I2(3)",
      "7.0(3)I2(2e)",
      "7.0(3)I2(2d)",
      "7.0(3)I2(2c)",
      "7.0(3)I2(2b)",
      "7.0(3)I2(2a)",
      "7.0(3)I2(2)",
      "7.0(3)I2(1a)",
      "7.0(3)I2(1)",
      "7.0(3)I1(3b)",
      "7.0(3)I1(3a)",
      "7.0(3)I1(3)",
      "7.0(3)I1(2)",
      "7.0(3)I1(1b)",
      "7.0(3)I1(1a)",
      "7.0(3)I1(1)",
      "7.0(3)F3(4)",
      "7.0(3)F3(3c)",
      "7.0(3)F3(3b)",
      "7.0(3)F3(3a)",
      "7.0(3)F3(3)",
      "7.0(3)F3(2)",
      "7.0(3)F3(1)",
      "7.0(3)F2(2)",
      "7.0(3)F2(1)",
      "7.0(3)F1(1)",
      "7.0(2)I2(2c)"
	);
	bugID = "CSCvi53896";
  break;
  case product_info.model =~ "35[0-9][0-9]": #3500 series
    version_list=make_list(
      "7.0(3)I7(4)",
      "7.0(3)I7(3)",
      "7.0(3)I7(2)",
      "7.0(3)I7(1)",
      "7.0(3)I6(2)",
      "7.0(3)I6(1)",
      "7.0(3)I5(2)",
      "7.0(3)I5(1)",
      "7.0(3)I4(8z)",
      "7.0(3)I4(8b)",
      "7.0(3)I4(8a)",
      "7.0(3)I4(8)",
      "7.0(3)I4(7)",
      "7.0(3)I4(6)",
      "7.0(3)I4(5)",
      "7.0(3)I4(4)",
      "7.0(3)I4(3)",
      "7.0(3)I4(2)",
      "7.0(3)I4(1)",
      "7.0(3)I3(1)",
      "7.0(3)I2(5)",
      "7.0(3)I2(4)",
      "7.0(3)I2(3)",
      "7.0(3)I2(2e)",
      "7.0(3)I2(2d)",
      "7.0(3)I2(2c)",
      "7.0(3)I2(2b)",
      "7.0(3)I2(2a)",
      "7.0(3)I2(2)",
      "7.0(3)I2(1a)",
      "7.0(3)I2(1)",
      "7.0(3)I1(3b)",
      "7.0(3)I1(3a)",
      "7.0(3)I1(3)",
      "7.0(3)I1(2)",
      "7.0(3)I1(1b)",
      "7.0(3)I1(1a)",
      "7.0(3)I1(1)",
      "7.0(3)F3(4)",
      "7.0(3)F3(3c)",
      "7.0(3)F3(3b)",
      "7.0(3)F3(3a)",
      "7.0(3)F3(3)",
      "7.0(3)F3(2)",
      "7.0(3)F3(1)",
      "7.0(3)F2(2)",
      "7.0(3)F2(1)",
      "7.0(3)F1(1)",
      "7.0(2)I2(2c)",
      "6.0(2)A8(9)",
      "6.0(2)A8(8)",
      "6.0(2)A8(7b)",
      "6.0(2)A8(7a)",
      "6.0(2)A8(7)",
      "6.0(2)A8(6)",
      "6.0(2)A8(5)",
      "6.0(2)A8(4a)",
      "6.0(2)A8(4)",
      "6.0(2)A8(3)",
      "6.0(2)A8(2)",
      "6.0(2)A8(10a)",
      "6.0(2)A8(10)",
      "6.0(2)A8(1)",
      "6.0(2)A7(2a)",
      "6.0(2)A7(2)",
      "6.0(2)A7(1a)",
      "6.0(2)A7(1)",
      "6.0(2)A6(8)",
      "6.0(2)A6(7)",
      "6.0(2)A6(6)",
      "6.0(2)A6(5b)",
      "6.0(2)A6(5a)",
      "6.0(2)A6(5)",
      "6.0(2)A6(4a)",
      "6.0(2)A6(4)",
      "6.0(2)A6(3a)",
      "6.0(2)A6(3)",
      "6.0(2)A6(2a)",
      "6.0(2)A6(2)",
      "6.0(2)A6(1a)",
      "6.0(2)A6(1)",
      "6.0(2)A4(6)",
      "6.0(2)A4(5)",
      "6.0(2)A4(4)",
      "6.0(2)A4(3)",
      "6.0(2)A4(2)",
      "6.0(2)A4(1)",
      "6.0(2)A3(4)",
      "6.0(2)A3(2)",
      "6.0(2)A3(1)",
      "6.0(2)A1(2d)",
      "6.0(2)A1(1f)",
      "6.0(2)A1(1e)",
      "6.0(2)A1(1d)",
      "6.0(2)A1(1c)",
      "6.0(2)A1(1b)",
      "6.0(2)A1(1a)",
      "6.0(2)A1(1)",
      "6.0(2)",
      "6.0(1)",
      "5.2(9a)",
      "5.2(9)N1(1)",
      "5.2(9)",
      "5.2(7)",
      "5.2(5)",
      "5.2(4)",
      "5.2(3a)",
      "5.2(3)",
      "5.2(1)",
      "5.1(6)",
      "5.1(5)",
      "5.1(4)",
      "5.1(3)",
      "5.1(1a)",
      "5.1(1)",
      "5.0(5)",
      "5.0(3)U5(1j)",
      "5.0(3)U5(1i)",
      "5.0(3)U5(1h)",
      "5.0(3)U5(1g)",
      "5.0(3)U5(1f)",
      "5.0(3)U5(1e)",
      "5.0(3)U5(1d)",
      "5.0(3)U5(1c)",
      "5.0(3)U5(1b)",
      "5.0(3)U5(1a)",
      "5.0(3)U5(1)",
      "5.0(3)U4(1)",
      "5.0(3)U3(2b)",
      "5.0(3)U3(2a)",
      "5.0(3)U3(2)",
      "5.0(3)U3(1)",
      "5.0(3)U2(2d)",
      "5.0(3)U2(2c)",
      "5.0(3)U2(2b)",
      "5.0(3)U2(2a)",
      "5.0(3)U2(2)",
      "5.0(3)U2(1)",
      "5.0(3)U1(2a)",
      "5.0(3)U1(2)",
      "5.0(3)U1(1d)",
      "5.0(3)U1(1c)",
      "5.0(3)U1(1b)",
      "5.0(3)U1(1a)",
      "5.0(3)U1(1)",
      "5.0(3)A1(2a)",
      "5.0(3)A1(2)",
      "5.0(3)A1(1)",
      "5.0(3)",
      "5.0(2a)",
      "4.2(8)",
      "4.2(6)",
      "4.2(4)",
      "4.2(3)",
      "4.2(2a)",
      "4.1(5)",
      "4.1(4)",
      "4.1(3)",
      "4.1(2)"
);
	bugID = "CSCvk70990";
  break;
  case product_info.model =~ "36[0-9][0-9]": #3600 series
    version_list=make_list(
      "7.0(3)F3(4)",
      "7.0(3)F3(3c)",
      "7.0(3)F3(3b)",
      "7.0(3)F3(3a)",
      "7.0(3)F3(3)",
      "7.0(3)F3(2)",
      "7.0(3)F3(1)",
      "7.0(3)F2(2)",
      "7.0(3)F2(1)",
      "7.0(3)F1(1)"
	);
	bugID = "CSCvm35213";
  break;
  case product_info.model =~ "(70|77)[0-9][0-9]": #7000 and 7700 series
    if (report_paranoia < 2) audit(AUDIT_PARANOID);
    vuln_list = [
      {'min_ver' : '0', 'fix_ver' : '6.2(22)'},
      {'min_ver' : '8.1', 'fix_ver' : '8.3(2)'}
    ];
	bugID = "CSCvm35215";
  break;
  case product_info.model =~ "90[0-9][0-9]": #9000 series
    version_list=make_list(
      "7.0(3)I7(4)",
      "7.0(3)I7(3)",
      "7.0(3)I7(2)",
      "7.0(3)I7(1)",
      "7.0(3)I6(2)",
      "7.0(3)I6(1)",
      "7.0(3)I5(2)",
      "7.0(3)I5(1)",
      "7.0(3)I4(8z)",
      "7.0(3)I4(8b)",
      "7.0(3)I4(8a)",
      "7.0(3)I4(8)",
      "7.0(3)I4(7)",
      "7.0(3)I4(6)",
      "7.0(3)I4(5)",
      "7.0(3)I4(4)",
      "7.0(3)I4(3)",
      "7.0(3)I4(2)",
      "7.0(3)I4(1)",
      "7.0(3)I3(1)",
      "7.0(3)I2(5)",
      "7.0(3)I2(4)",
      "7.0(3)I2(3)",
      "7.0(3)I2(2e)",
      "7.0(3)I2(2d)",
      "7.0(3)I2(2c)",
      "7.0(3)I2(2b)",
      "7.0(3)I2(2a)",
      "7.0(3)I2(2)",
      "7.0(3)I2(1a)",
      "7.0(3)I2(1)",
      "7.0(3)I1(3b)",
      "7.0(3)I1(3a)",
      "7.0(3)I1(3)",
      "7.0(3)I1(2)",
      "7.0(3)I1(1b)",
      "7.0(3)I1(1a)",
      "7.0(3)I1(1)",
      "7.0(3)F3(4)",
      "7.0(3)F3(3c)",
      "7.0(3)F3(3b)",
      "7.0(3)F3(3a)",
      "7.0(3)F3(3)",
      "7.0(3)F3(2)",
      "7.0(3)F3(1)",
      "7.0(3)F2(2)",
      "7.0(3)F2(1)",
      "7.0(3)F1(1)",
      "7.0(2)I2(2c)"
	);
	bugID = "CSCvi53896";
  break;
  case product_info.model =~ "95[0-9][0-9]": #9500 series
    version_list=make_list(
      "7.0(3)F3(4)",
      "7.0(3)F3(3c)",
      "7.0(3)F3(3b)",
      "7.0(3)F3(3a)",
      "7.0(3)F3(3)",
      "7.0(3)F3(2)",
      "7.0(3)F3(1)",
      "7.0(3)F2(2)",
      "7.0(3)F2(1)",
      "7.0(3)F1(1)"
	);
	bugID = "CSCvm35213";
  break;
  case product_info.device != 'Nexus': #This is purposeful. Case fall through for failure specific conditions.
  case default:
    audit(AUDIT_HOST_NOT, 'affected');
}
reporting = make_array(
'port'     , 0,
'disable_caveat' , 1,
'severity' , SECURITY_HOLE,
'version'  , product_info['version'],
'bug_id'   , bugID
);

cisco::check_and_report(product_info:product_info, reporting:reporting, vuln_versions:version_list, vuln_ranges:vuln_list);
