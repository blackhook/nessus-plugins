#TRUSTED 23b157108dd45ac6dfd4459835f8e15e1b2ee4e6a0f4feb314cd1f607696cec0083c20d76fd0e920f2430560c6e45493a6ef837011b4d37a15612c67d812b73903bd55f5ea3b60ccc497591d1f9077b90936ab15e55e62c9e9807a87362963b7d669197e1cd2e48af24a4775762c73424cecdd5ff57927dd28fa39f9e225f5c3dcdf15655f4e79285b385545b20675a9c3b3abfa733da582f1133f7545627ff6a1795e76e6ee2e40b3e4f6193e89d592464bd9553951f8d1b239ce626f5b43c423150ac24353eaddbc300c94c8efca063425d0ec1a48d5c455aaa238d97392f2417de87c532d84c7e5e9f65e6409c6d43eb16200dbeb730d3bb827ba74da338149521fdc3d4da8f78e0031c2488d39f4104c772dcf489e23adf58bb78ac9f351b80d11fe9e73d0198ef82e42577e8a52da259e53284916151dfd549785d275debad1bf0dbb0798530e7d6b142ec748d75a2a5ae904868b4fd1b1caea430df921c4074d0fa88eb76c12cc35fbfa0dabcc30cec35c6c6e562cbb4058818f4f36cdf7469abe4c55c9af688b29139442944fef7a672a58e93b3be841110fa5b4aa9467c54351e85cc914a36e18aa913f782fd4c00d5edd34bcb6cee2b8316d436c966c0cd2fea8a545bec0b9234c18f028350b8b8e57d0be5ca3caba464a3a1d4b869fe6e19aa7303ee9d09f7c412b135d61a477ca2bebec1b72b3893f7f037d6c97
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125391);
  script_version("1.6");
  script_cvs_date("Date: 2019/12/20");

  script_cve_id(
    "CVE-2019-1597",
    "CVE-2019-1598"
    );
  script_bugtraq_id(107394);
  script_xref(name:"CWE", value:"CWE-20");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd40241");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd57308");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve02855");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve02858");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve02865");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve02867");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve02871");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve57816");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve57820");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve58224");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190306-nxosldap");

  script_name(english:"Cisco FXOS and NX-OS Lightweight Directory Access Protocol Denial of Service Vulnerabilities");
  script_summary(english:"Checks the version of Cisco Unified Computing System (Managed)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco FXOS Software and
Cisco NX-OS Software are affected by multiple vulnerabilities which
could allow an unauthenticated, remote attacker to cause a denial of 
service attack (DoS).
The vulnerabilities are due to the improper parsing of LDAP packets
by an affected device. An attacker could exploit these vulnerabilities
by sending an LDAP packet crafted using Basic Encoding Rules (BER) to
an affected device. The LDAP packet must have a source IP address of
an LDAP server configured on the targeted device. A successful exploit
could cause the affected device to reload, resulting in a DoS condition.

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190306-nxosldap
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?453a1923");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd40241");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd57308");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve02855");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve02858");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve02865");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve02867");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve02871");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve57816");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve57820");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve58224");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed / recommended version referenced in Cisco Security
Advisories.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1597");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/24");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco NX-OS Software");

cbi = NULL;

if (('MDS' >< product_info['device']) && (product_info['model'] =~ '^90[0-9][0-9]'))
  cbi = "CSCve57820, CSCve02867";
else if ('Nexus' >< product_info['device'])
{
  if (product_info['model'] =~ '^30[0-9][0-9]')
    cbi = "CSCve58224, CSCve02858";
  else if (product_info['model'] =~ '^35[0-9][0-9]')
    cbi = "CSCve02871";
  else if (product_info['model'] =~ '^7[07][0-9][0-9]')
    cbi = "CSCve57820, CSCve02867";
  else if (product_info['model'] =~ '^90[0-9][0-9]')
    cbi = "CSCve02865, CSCve57816";
}
else if (('UCS' >< product_info['device']) && (product_info['model'] =~ '^6[2-3][0-9][0-9]'))
    cbi = "CSCve02855";

if (empty_or_null(cbi))
  audit(AUDIT_HOST_NOT, 'affected');

version_list = make_list (
  "4.1(2)",
  "4.1(3)",
  "4.1(4)",
  "4.1(5)",
  "5.0(2a)",
  "5.0(3)",
  "5.0(5)",
  "5.0(1a)",
  "5.0(1b)",
  "5.0(4)",
  "5.0(4b)",
  "5.0(4c)",
  "5.0(4d)",
  "5.0(7)",
  "5.0(8)",
  "5.0(8a)",
  "5.0(2)",
  "4.2(2a)",
  "4.2(3)",
  "4.2(4)",
  "4.2(6)",
  "4.2(8)",
  "5.1(1)",
  "5.1(1a)",
  "5.1(3)",
  "5.1(4)",
  "5.1(5)",
  "5.1(6)",
  "5.1(2)",
  "5.2(1)",
  "5.2(3a)",
  "5.2(4)",
  "5.2(5)",
  "5.2(7)",
  "5.2(9)",
  "5.2(3)",
  "5.2(9a)",
  "5.2(2)",
  "5.2(2a)",
  "5.2(2d)",
  "5.2(2s)",
  "5.2(6)",
  "5.2(6b)",
  "5.2(8)",
  "5.2(8a)",
  "5.2(6a)",
  "5.2(8b)",
  "5.2(8c)",
  "5.2(8d)",
  "5.2(8e)",
  "5.2(8f)",
  "5.2(8g)",
  "5.2(8h)",
  "5.2(8i)",
  "6.1(1)",
  "6.1(2)",
  "6.1(3)",
  "6.1(4)",
  "6.1(4a)",
  "6.1(5)",
  "6.1(3)S5",
  "6.1(3)S6",
  "6.1(5a)",
  "5.0(3)A1(1)",
  "5.0(3)A1(2)",
  "5.0(3)A1(2a)",
  "5.0(3)U1(1)",
  "5.0(3)U1(1a)",
  "5.0(3)U1(1b)",
  "5.0(3)U1(1d)",
  "5.0(3)U1(2)",
  "5.0(3)U1(2a)",
  "5.0(3)U1(1c)",
  "5.0(3)U2(1)",
  "5.0(3)U2(2)",
  "5.0(3)U2(2a)",
  "5.0(3)U2(2b)",
  "5.0(3)U2(2c)",
  "5.0(3)U2(2d)",
  "5.0(3)U3(1)",
  "5.0(3)U3(2)",
  "5.0(3)U3(2a)",
  "5.0(3)U3(2b)",
  "5.0(3)U4(1)",
  "5.0(3)U5(1)",
  "5.0(3)U5(1a)",
  "5.0(3)U5(1b)",
  "5.0(3)U5(1c)",
  "5.0(3)U5(1d)",
  "5.0(3)U5(1e)",
  "5.0(3)U5(1f)",
  "5.0(3)U5(1g)",
  "5.0(3)U5(1h)",
  "5.0(3)U5(1i)",
  "5.0(3)U5(1j)",
  "6.0(1)",
  "6.0(2)",
  "6.0(3)",
  "6.0(4)",
  "6.0(2)A1(1)",
  "6.0(2)A1(1a)",
  "6.0(2)A1(1b)",
  "6.0(2)A1(1c)",
  "6.0(2)A1(1d)",
  "6.0(2)A1(1e)",
  "6.0(2)A1(1f)",
  "6.0(2)A1(2d)",
  "6.0(2)A3(1)",
  "6.0(2)A3(2)",
  "6.0(2)A3(4)",
  "6.0(2)A4(1)",
  "6.0(2)A4(2)",
  "6.0(2)A4(3)",
  "6.0(2)A4(4)",
  "6.0(2)A4(5)",
  "6.0(2)A4(6)",
  "6.0(2)A6(1)",
  "6.0(2)A6(1a)",
  "6.0(2)A6(2)",
  "6.0(2)A6(2a)",
  "6.0(2)A6(3)",
  "6.0(2)A6(3a)",
  "6.0(2)A6(4)",
  "6.0(2)A6(4a)",
  "6.0(2)A6(5)",
  "6.0(2)A6(5a)",
  "6.0(2)A6(5b)",
  "6.0(2)A6(6)",
  "6.0(2)A6(7)",
  "6.0(2)A6(8)",
  "6.0(2)A7(1)",
  "6.0(2)A7(1a)",
  "6.0(2)A7(2)",
  "6.0(2)A7(2a)",
  "6.0(2)A8(1)",
  "6.0(2)A8(2)",
  "6.0(2)A8(3)",
  "6.0(2)A8(4)",
  "6.0(2)A8(4a)",
  "6.0(2)A8(5)",
  "6.0(2)A8(6)",
  "6.0(2)A8(7)",
  "6.0(2)A8(7a)",
  "6.0(2)A8(7b)",
  "6.0(2)A8(8)",
  "6.0(2)A8(9)",
  "6.0(2)A8(10a)",
  "6.0(2)A8(10)",
  "6.0(2)U1(1)",
  "6.0(2)U1(2)",
  "6.0(2)U1(1a)",
  "6.0(2)U1(3)",
  "6.0(2)U1(4)",
  "6.0(2)U2(1)",
  "6.0(2)U2(2)",
  "6.0(2)U2(3)",
  "6.0(2)U2(4)",
  "6.0(2)U2(5)",
  "6.0(2)U2(6)",
  "6.0(2)U3(1)",
  "6.0(2)U3(2)",
  "6.0(2)U3(3)",
  "6.0(2)U3(4)",
  "6.0(2)U3(5)",
  "6.0(2)U3(6)",
  "6.0(2)U3(7)",
  "6.0(2)U3(8)",
  "6.0(2)U3(9)",
  "6.0(2)U4(1)",
  "6.0(2)U4(2)",
  "6.0(2)U4(3)",
  "6.0(2)U4(4)",
  "6.0(2)U5(1)",
  "6.0(2)U5(2)",
  "6.0(2)U5(3)",
  "6.0(2)U5(4)",
  "6.0(2)U6(1)",
  "6.0(2)U6(2)",
  "6.0(2)U6(3)",
  "6.0(2)U6(4)",
  "6.0(2)U6(5)",
  "6.0(2)U6(6)",
  "6.0(2)U6(7)",
  "6.0(2)U6(8)",
  "6.0(2)U6(1a)",
  "6.0(2)U6(2a)",
  "6.0(2)U6(3a)",
  "6.0(2)U6(4a)",
  "6.0(2)U6(5a)",
  "6.0(2)U6(5b)",
  "6.0(2)U6(5c)",
  "6.0(2)U6(9)",
  "6.0(2)U6(10)",
  "6.1(2)I1(3)",
  "6.1(2)I1(1)",
  "6.1(2)I1(2)",
  "6.1(2)I2(1)",
  "6.1(2)I2(2)",
  "6.1(2)I2(2a)",
  "6.1(2)I2(3)",
  "6.1(2)I2(2b)",
  "6.1(2)I3(1)",
  "6.1(2)I3(2)",
  "6.1(2)I3(3)",
  "6.1(2)I3(3.78)",
  "6.1(2)I3(4)",
  "6.1(2)I3(3a)",
  "6.1(2)I3(4a)",
  "6.1(2)I3(4b)",
  "6.1(2)I3(4c)",
  "6.1(2)I3(4d)",
  "6.1(2)I3(4e)",
  "6.1(2)I3(5)",
  "6.1(2)I3(5a)",
  "6.1(2)I3(5b)",
  "6.1(2)I3(3b)",
  "6.2(2)",
  "6.2(2a)",
  "6.2(6)",
  "6.2(6b)",
  "6.2(8)",
  "6.2(8a)",
  "6.2(8b)",
  "6.2(10)",
  "6.2(12)",
  "6.2(18)",
  "6.2(16)",
  "6.2(14b)",
  "6.2(14)",
  "6.2(14a)",
  "6.2(6a)",
  "6.2(1)",
  "6.2(3)",
  "6.2(5)",
  "6.2(5a)",
  "6.2(5b)",
  "6.2(7)",
  "6.2(9)",
  "6.2(9a)",
  "6.2(9b)",
  "6.2(9c)",
  "6.2(11)",
  "6.2(11b)",
  "6.2(11c)",
  "6.2(11d)",
  "6.2(11e)",
  "6.2(13)",
  "6.2(13a)",
  "6.2(13b)",
  "6.2(15)",
  "6.2(17)",
  "6.2(19)",
  "7.0(3)",
  "7.0(2)I2(2c)",
  "7.0(3)F1(1)",
  "7.0(3)I1(1)",
  "7.0(3)I1(1a)",
  "7.0(3)I1(1b)",
  "7.0(3)I1(2)",
  "7.0(3)I1(3)",
  "7.0(3)I1(3a)",
  "7.0(3)I1(3b)",
  "7.0(3)I2(2a)",
  "7.0(3)I2(2b)",
  "7.0(3)I2(2c)",
  "7.0(3)I2(2d)",
  "7.0(3)I2(2e)",
  "7.0(3)I2(3)",
  "7.0(3)I2(4)",
  "7.0(3)I2(5)",
  "7.0(3)I2(1)",
  "7.0(3)I2(1a)",
  "7.0(3)I2(2)",
  "7.0(3)I3(1)",
  "7.0(3)I4(1)",
  "7.0(3)I4(2)",
  "7.0(3)I4(3)",
  "7.0(3)I4(4)",
  "7.0(3)I4(5)",
  "7.0(3)I4(6)",
  "7.0(3)I5(1)",
  "7.0(3)I5(2)",
  "7.0(3)I6(1)",
  "7.0(3)I6(2)",
  "7.0(3)IX1(2)",
  "7.0(3)IX1(2a)",
  "7.2(0)D1(1)",
  "7.2(1)D1(1)",
  "7.2(2)D1(2)",
  "7.2(2)D1(1)",
  "7.3(0)D1(1)",
  "7.3(0)DX(1)",
  "7.3(0)DY(1)",
  "7.3(1)D1(1B)",
  "7.3(1)D1(1)",
  "7.3(1)DY(1)",
  "7.3(1)N1(0.1)",
  "8.0(1)",
  "8.1(1)",
  "8.1(2)",
  "8.1(2a)",
  "8.1(1a)",
  "8.1(1b)"
);

workarounds = make_list(CISCO_WORKAROUNDS['ldap']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , cbi
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
