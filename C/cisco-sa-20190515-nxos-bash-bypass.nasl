#TRUSTED 462dfea7fed67553b8fcf67e6a7b2e8e7e5225e8125bcb797dbb21002919f4243c27757e8fe5a86b354a8a5184e97b88ac2e366cb3a531aedf4f96ff38025c0776ddebd3d1f4cc66a4e4b58922c985d58dc5b2d38650301350ac342d6ad123743c92bf7044c9812e80c03a4a967a8a44b91e8ed76f43507744c5f8542dea2658a8b6034e54b5647543962f341e2e9f8e1baeb7fe0495689ab3595ade6b54b4071ce6ac7884db174213a3bc9976d3f96d9168046600126d48d73c8399361e8f5bfc6f59cf2895b7d528a9bbd793ec2c7cd8ea8815bcd0b380b6712b58a83496023a79c565969aea2d431c29f5bfeaab6702ffbf02ad91286e37730723b949880f72b28bde76fbb9c47cfec5b918f4d527601ad0ecdde7757b209f7fe292e7e231d032f593e59e0c9c650e1097d0e5d1cb9de0819e89c51745730fa7459cd8a5070884f3736f5e77e579302a6e69c18654ee3689cb18ffefe11ffc676971c9e4320ad641db4a8c637fd35100552a651ffebc27d07c6901b654c75eae8b0ed4a9b3ada194cf27f74ad3c29f05da0cc6c5292d3a197b94b57638ecd0513c2dec63b41fdc45b09639178c2e6cc59217c4b8635a77a32422222caa5a07ec727f35cf02aeb9e49be80fb502d1ff427bc5477bd57cd8a02b8a6d370d406f5d00694d225e57205b8933e8c726e6798ac3c00340afc1b2556779d110f14a581870e02395c6
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(132678);
  script_version("1.4");
  script_cvs_date("Date: 2020/01/09");

  script_cve_id("CVE-2019-1730");
  script_bugtraq_id(108397);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh76090");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj01472");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj01497");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190515-nxos-bash-bypass");
  script_xref(name:"IAVA", value:"2019-A-0173");

  script_name(english:"Cisco NX-OS Software Bash Bypass Guest Shell (cisco-sa-20190515-nxos-bash-bypass)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by following vulnerability in the Bash shell
implementation due to the incorrect implementation of a CLI command that allows a Bash command to be incorrectly invoked
on the Guest Shell CLI. An authenticated, local attacker can exploit this, by authenticating to the device and entering
a crafted command at the Guest Shell prompt, to bypass the limited command set of the restricted Guest Shell and
execute commands at the privilege level of a network-admin user outside of the Guest Shell.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190515-nxos-bash-bypass
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d0c1d1a8");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh76090");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj01472");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj01497");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvh76090, CSCvj01472, and CSCvj01497.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1730");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

if ('Nexus' >!< product_info.device)
  audit(AUDIT_HOST_NOT, 'affected');

if (product_info.model =~ '^(3[05]|90)[0-9][0-9]')
  cbi = 'CSCvh76090';
else if (product_info.model =~ '^(36|95)[0-9][0-9]')
  cbi = 'CSCvj01497';
else if (product_info.model =~ '^(70|77)[0-9][0-9]')
  cbi = 'CSCvj01472';
else audit(AUDIT_HOST_NOT, 'affected');

version_list=make_list(
  '7.0(3)',
  '7.0(0)N1(1)',
  '7.0(1)N1(1)',
  '7.0(1)N1(3)',
  '7.0(2)I2(2c)',
  '7.0(2)N1(1)',
  '7.0(2)N1(1a)',
  '7.0(3)F1(1)',
  '7.0(3)F2(1)',
  '7.0(3)F2(2)',
  '7.0(3)F3(1)',
  '7.0(3)F3(2)',
  '7.0(3)F3(3)',
  '7.0(3)F3(3a)',
  '7.0(3)F3(4)',
  '7.0(3)F3(3c)',
  '7.0(3)F3(3b)',
  '7.0(3)I1(1)',
  '7.0(3)I1(1a)',
  '7.0(3)I1(1b)',
  '7.0(3)I1(2)',
  '7.0(3)I1(3)',
  '7.0(3)I1(3a)',
  '7.0(3)I1(3b)',
  '7.0(3)I2(2a)',
  '7.0(3)I2(2b)',
  '7.0(3)I2(2c)',
  '7.0(3)I2(2d)',
  '7.0(3)I2(2e)',
  '7.0(3)I2(3)',
  '7.0(3)I2(4)',
  '7.0(3)I2(5)',
  '7.0(3)I2(1)',
  '7.0(3)I2(1a)',
  '7.0(3)I2(2)',
  '7.0(3)I3(1)',
  '7.0(3)I4(1)',
  '7.0(3)I4(2)',
  '7.0(3)I4(3)',
  '7.0(3)I4(4)',
  '7.0(3)I4(5)',
  '7.0(3)I4(6)',
  '7.0(3)I4(7)',
  '7.0(3)I4(8)',
  '7.0(3)I4(8a)',
  '7.0(3)I4(8b)',
  '7.0(3)I4(8z)',
  '7.0(3)I7(5a)',
  '7.0(3)I5(1)',
  '7.0(3)I5(2)',
  '7.0(3)I6(1)',
  '7.0(3)I6(2)',
  '7.0(3)I7(1)',
  '7.0(3)I7(2)',
  '7.0(3)I7(3)',
  '7.0(3)I7(5a)'
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();


reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info.version,
  'bug_id'   , cbi
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
