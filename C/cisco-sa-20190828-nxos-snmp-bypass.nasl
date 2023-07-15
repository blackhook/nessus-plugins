#TRUSTED 4b666d2eecb4a10cf4c1c441f1188cd1fb2328b188944a9e2b390b5d9efe90358a59b3494bd12a111ba8c6c7e5f4a5d3ca93883dc881ab54e956e5e9cfbdd2ce2a32e3357979472d3c21ea4d4c8fa4a693063aa3ad01f686a87abdd560ef2204d9f38a83887fe51ab0222c229794adb60153fccd0cfd06d8c33e09d9b6305e7c72a177b4f026451a67b4517101c45e22a3bdc18179eb86cd8476de89d4de1a03ca4326011310b8fb710f25d716f7e5edf3307c5b8582dffc22132ab39a225ad91d1d5988ee1dbdeb663f3d9f20f496440dec33926ac52e7eb8f5b5baae7b774d1832a9036caaa70e908d8d5b93a1397660dfa5cb00839aa3063fab08b7c8d96a34d2400245a04492fcfbdb1b98b677530e8340c877d870f8be31e3cafbc8e92c81a46d71255abf4e903309ae38a0ebefb49e9c4f1c05d4978dda33d22dc1f707d7ae9536eab8b71795f24deda04be0452432e3fede84893c8d235eb780dfc486a2216240d0bf62aef407227e2aa85dd650489f6eb925e3bd6b3b91b63c2f8304d3d22c062da3ebfe0e0750c4d05f1f6a6d8de96095dca11af885a72854b0eaaf5110559c0f9e24c2ef1b34c97c15c0c99c88f1876a0f100efa4330e7338879db0bd7f78bc7ecfb307357f5b43cf74e7471bcf8e95b06cafcb850d499cd24be946686e3e303902f2ce0c171cb27647eafd4f769a7d787077571b7e3ebcf3d5b5d
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(128760);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2019/11/27");

  script_cve_id("CVE-2019-1969");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo17439");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190828-nxos-snmp-bypass");
  script_xref(name:"IAVA", value:"2019-A-0317");

  script_name(english:"Cisco NX-OS Software SNMP Access Control List Configuration Name Bypass Vulnerability (CVE-2019-1969)");
  script_summary(english:"Checks the version of Cisco NX-OS Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by a vulnerability that allows an 
unauthenticated, remote attacker to perform SNMP polling of an affected device, even when it is configured to deny SNMP
traffic. The cause of this vulnerability is an incorrect length check when the configured ACL name is 32 ASCII
characters (the maximum length). Though the attacker has no control over the configuration of the SNMP ACL name, an
attacker can exploit this vulnerability by performing SNMP polling of an affected device. This allows the attacker to
perform SNMP polling that should have been denied.

With SNMP Version 2c or earlier, to exploit this vulnerability the attacker must know the SNMP read-only community
string for the affected system. The community string is a password applied to a device which restricts both read-only
and read-write access to the SNMP data on the device. Community strings should be treated like all passwords: they
must be non-trivial and changed at regular intervals in accordance with network security policies. 

With SNMP Version 3, the attacker must have user credentials for the affected system.

Please see the included Cisco BID and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190828-nxos-snmp-bypass
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?307f0135");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo17439");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvo17439 or apply the workarounds from the vendor
advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1969");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/13");

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

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

if ('Nexus' >!< product_info.device || product_info.model !~ '^(3[056]|9[05])[0-9][0-9]')
  audit(AUDIT_HOST_NOT, 'affected');

version_list=make_list(
  '7.0(3)I7(1)',
  '7.0(3)I7(2)',
  '7.0(3)I7(3)',
  '7.0(3)I7(4)',
  '7.0(3)I7(5)',
  '7.0(3)I7(5a)',
  '7.0(3)I7(3z)',
  '9.2(1)',
  '9.2(2)',
  '9.2(2t)',
  '7.0(3)IA7(1)',
  '7.0(3)IA7(2)',
  '7.0(3)IM7(2)',
  '7.0(3)I7(1)',
  '7.0(3)I7(1)',
  '7.0(3)I7(2)',
  '7.0(3)I7(2)',
  '7.0(3)I7(3)',
  '7.0(3)I7(3)',
  '7.0(3)I7(4)',
  '7.0(3)I7(4)',
  '7.0(3)I7(5)',
  '7.0(3)I7(5)',
  '7.0(3)I7(5a)',
  '7.0(3)I7(5a)',
  '7.0(3)I7(3z)',
  '7.0(3)I7(3z)',
  '9.2(1)',
  '9.2(1)',
  '9.2(2)',
  '9.2(2)',
  '9.2(2t)',
  '7.0(3)IA7(1)',
  '7.0(3)IA7(2)',
  '7.0(3)IM7(2)'
);

workarounds = make_list(CISCO_WORKAROUNDS['snmp']);
workaround_params = {'acl' : 1};

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'cmds'     , make_list('show running-config | include snmp-server'),
  'bug_id'   , 'CSCvo17439'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list,
  switch_only:TRUE
);
