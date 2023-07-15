#TRUSTED 307d706eb21501b98a4d85efe166d63ef53c9a5f72835c25eafac38b39101e6019fc964b0cf27a6e5b8ed86b0d4b641d5cd2b6023bb59eba54ead8caeb32f82b9f024dc6dcf38864164c1616b9677184f5b24d5adaeb68b41abb1830f8689d16ac85c8c4fe1f5c1efd6036368ff9cc6a91ebf93a48c11eb46341ca581f1a08101f45b1f4a0ff2f6e8325f5c6a39c6f665625909b210e59e2b65ca7563494d75e5e15b7716b49c46ff4538cc4548c4dcb0db120a49d290c09ad4b1eadb131412b202bcd887fb0e350ee56877581e4897a9b12b580bcb9e9d5191d7cb9f6c6f850927b78dbad9bee4db0aeec2452c54f3938693ce31b435a306b51f58ee469a711ef22eeffebc8f5c738f6a47c4ffd44d62c4afc38da9dcde88d0e6e245cd19d22416a9feeea3104ccf4f0ebf25839930f9bede3f173efad70da3f27b0c42c5c15bd2d3d4d37e33662ee9b03f0537573f8c8ea1e43ee41c628c80c7a139244abd6298617625ab248c494092db916a63d2a1421e55bdd82bf81f82b147e8d41fe83ec8e07f77b0a9f017863544d5d9042a82a211355b7811a0d5bef4ea5e92cdee40dee3e333dbbd2f33e2205c11e8fb3da184a38ee9791ee079123248ccdd26933708a050960f1ae60d4c915639a5d15327abd9edf2fcef32768b23aa8fc38110bb83e27b931cbe5d5cdefb198cb6a6e5149d00ad94c142c964f84e1de6c5f29ab
#
# Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(122751);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/19");

  script_cve_id("CVE-2019-1614");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj17615");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk51420");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk51423");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190306-nxos-NXAPI-cmdinj");
  script_xref(name:"IAVA", value:"2019-A-0159");

  script_name(english:"Cisco NX-OS Software NX-API Command Injection Vulnerability");
  script_summary(english:"Checks the version of Cisco NX-OS Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is
affected by a vulnerability in the NX-API feature of Cisco NX-OS
Software could allow an authenticated, remote attacker to execute
arbitrary commands with root privileges. The vulnerability is due to
incorrect input validation of user-supplied data by the NX-API
subsystem. An attacker could exploit this vulnerability by sending
malicious HTTP or HTTPS packets to the management interface of an
affected system that has the NX-API feature enabled. A successful
exploit could allow the attacker to perform a command-injection attack
and execute arbitrary commands with root privileges.

Note: NX-API is disabled by default.

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190306-nxos-NXAPI-cmdinj
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?95a3a64a");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-70757");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj17615");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk51420");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk51423");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1614");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/11");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco NX-OS Software");

cbi = "";

if ('MDS' >< product_info.device && product_info.model =~ '^90[0-9][0-9]')
  cbi = "CSCvk51420";
else if ('Nexus' >< product_info.device)
{
  if (product_info.model =~ '^3[05][0-9][0-9]')
    cbi = "CSCvj17615";
  else if (product_info.model =~ '^(20|5[56]|60)[0-9][0-9]')
    cbi = "CSCvk51423";
  else if (product_info.model =~ '^7[07][0-9][0-9]')
    cbi = "CSCvk51420";
  else if (product_info.model =~ '^90[0-9][0-9]')
    cbi = "CSCvj17615";
  else audit(AUDIT_HOST_NOT, 'affected');
}
else audit(AUDIT_HOST_NOT, 'affected');

version_list=make_list(
  "8.3(1)",
  "8.2(2)",
  "8.2(1)",
  "8.1(2a)",
  "8.1(2)",
  "8.1(1a)",
  "8.1(1)",
  "8.0(1)",
  "7.3(3)N1(1)",
  "7.3(2)N1(1)",
  "7.3(2)D1(3a)",
  "7.3(2)D1(3)",
  "7.3(2)D1(2)",
  "7.3(2)D1(1)",
  "7.3(1)N1(1)",
  "7.3(1)DY(1)",
  "7.3(1)D1(1)",
  "7.3(0)N1(1)",
  "7.3(0)DY(1)",
  "7.3(0)DX(1)",
  "7.3(0)D1(1)",
  "7.2(2)D1(2)",
  "7.2(2)D1(1)",
  "7.2(1)D1(1)",
  "7.2(0)D1(1)",
  "7.0(3)IX1(2a)",
  "7.0(3)IX1(2)",
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
  "7.0(3)I2(1)",
  "7.0(3)I1(3b)",
  "7.0(3)I1(3a)",
  "7.0(3)I1(3)",
  "7.0(3)I1(2)",
  "7.0(3)I1(1b)",
  "7.0(3)I1(1a)",
  "7.0(3)I1(1)",
  "7.0(2)I2(2c)",
  "6.1(2)I3(5b)",
  "6.1(2)I3(5a)",
  "6.1(2)I3(5)",
  "6.1(2)I3(4e)",
  "6.1(2)I3(4d)",
  "6.1(2)I3(4c)",
  "6.1(2)I3(4b)",
  "6.1(2)I3(4a)",
  "6.1(2)I3(4)",
  "6.1(2)I3(3a)",
  "6.1(2)I3(3)",
  "6.1(2)I3(2)",
  "6.1(2)I3(1)",
  "6.1(2)I2(3)",
  "6.1(2)I2(2b)",
  "6.1(2)I2(2a)",
  "6.1(2)I2(2)",
  "6.1(2)I2(1)",
  "6.1(2)I1(3)",
  "6.1(2)I1(2)",
  "6.1(2)I1(1)",
  "6.1(2)",
  "6.0(2)U6(9)",
  "6.0(2)U6(8)",
  "6.0(2)U6(7)",
  "6.0(2)U6(6)",
  "6.0(2)U6(5c)",
  "6.0(2)U6(5b)",
  "6.0(2)U6(5a)",
  "6.0(2)U6(5)",
  "6.0(2)U6(4a)",
  "6.0(2)U6(4)",
  "6.0(2)U6(3a)",
  "6.0(2)U6(3)",
  "6.0(2)U6(2a)",
  "6.0(2)U6(2)",
  "6.0(2)U6(1a)",
  "6.0(2)U6(10)",
  "6.0(2)U6(1)",
  "6.0(2)U5(4)",
  "6.0(2)U5(3)",
  "6.0(2)U5(2)",
  "6.0(2)U5(1)",
  "6.0(2)U4(4)",
  "6.0(2)U4(3)",
  "6.0(2)U4(2)",
  "6.0(2)U4(1)",
  "6.0(2)U3(9)",
  "6.0(2)U3(8)",
  "6.0(2)U3(7)",
  "6.0(2)U3(6)",
  "6.0(2)U3(5)",
  "6.0(2)U3(4)",
  "6.0(2)U3(3)",
  "6.0(2)U3(2)",
  "6.0(2)U3(1)",
  "6.0(2)U2(6)",
  "6.0(2)U2(5)",
  "6.0(2)U2(4)",
  "6.0(2)U2(3)",
  "6.0(2)U2(2)",
  "6.0(2)U2(1)",
  "6.0(2)U1(4)",
  "6.0(2)U1(3)",
  "6.0(2)U1(2)",
  "6.0(2)U1(1a)",
  "6.0(2)U1(1)",
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
  "5.0(3)U1(1)"
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['nxos_nxapi'];

reporting = make_array(
'port'     , 0,
'severity' , SECURITY_HOLE,
'version'  , product_info['version'],
'bug_id'   , cbi
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);

