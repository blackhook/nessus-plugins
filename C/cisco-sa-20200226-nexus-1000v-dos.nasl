#TRUSTED 14d5352dffb2cc20f25079c778e197f376980ba4ec20a64566fd891c87bd85f97be8dd2a0a300728124531dcf69b63b7005e5842adde5827e4b8d6470b060dc17686f62fd2339db5765824f6662406891e853d55565b71f37ae76bd5865dd4dc06c871604beca174f7af6a953031030d30b4fc5d67fbb79681f8ab5b8d4ebdf76c7deb122051a344ffd3f6614fb4eb9848219b2a7c11635eec8daebb92c596ecddc73f56fe962144cfe446c31c57d232f47e151cf5c9fc046c7c0f745b7b902d21de2a74e759d013ac2b62a35c2a90a47511f7e4273499deaf5d9689bec49c7a2510b8aa442b0bf3f865a18d788cf65d1b81d7f5717e61ffb439760c3b4153b996bfabddf1a06005d5a4efce1e0f9bb42a009f0ff55ed45f1a6f6fcebfb2b153c11a09726fa507f959ad9c088f7421643e56cf69a556707e5fac255468d6e60fa7e9b83e862e5c1674e77444f08e4fc06c7b2fd4859c636c30b08b6bc3229d9355fc678cfe6ec19f8b6e377946a36db6962b5967e965ed5f47c6660a598361b85d2e89b0967bd0353c17fb516ebe60b590fdf2b295694aff74ae2c14dfbc4ef1735e595fc8b5ff0b4571661614bc2a0194632877515d959f9d7c4ae5b36938c350454d838b7b71bee995331b2362e6654144be4decc143fcbcc7e8830d90906ea553bce0e1c88fd4f4f88b71d24fe0d3b978baf468257ac0b45b8e296407318f
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134417);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/06");

  script_cve_id("CVE-2020-3168");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp26722");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20200226-nexus-1000v-dos");
  script_xref(name:"IAVA", value:"2020-A-0087");

  script_name(english:"Cisco Nexus 1000V Switch for VMware vSphere Secure Login Enhancements Denial of Service Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is vulnerable to denial of service (DoS) due to missing patch. (cisco-sa-20200226-nexus-1000v-dos)");
  script_set_attribute(attribute:"description", value:
"A denial of service (DoS) vulnerability exists in Cisco Nexus 1000V Switch due to issues with the Secure Login 
Enhancements. An unauthenticated, remote attacker can exploit this issue, via overloading the login system, 
to cause the system to stop responding.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20200226-nexus-1000v-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1001187e");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-73749");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp26722");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvp26722");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3168");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/11");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

if ('Nexus' >!< product_info.device || product_info.model !~ '^10[0-9][0-9][Vv]')
  audit(AUDIT_HOST_NOT, 'affected');

version_list=make_list(
  '5.2(1)SV3(4.1a)'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['login_block-for'];

#Cisco's 'workaround' in this case will trigger a lower priority bug, but they are technically not vulnerable to this.
#If client is complaining, point towards documentation that describes work around as short term fix.

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvp26722'
);

cisco::check_and_report(
  product_info:product_info, 
  reporting:reporting, 
  vuln_versions:version_list,
  workarounds:workarounds,
  workaround_params:workaround_params
);
