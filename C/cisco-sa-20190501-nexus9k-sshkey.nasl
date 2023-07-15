#TRUSTED a26cd10107166afd018e3360cf2e0196fcf5a1ae633c0e7dcbfb57b0874140645f3558d11d7813a5a81cd72e83333c94a1b1409b773d4ac5809df1f70a391c59e720d7e2d3921fac8523371ef55c46c3fb8c3de1650ebd98e8bb3a2a720d0752bd7b5b30f2a3199720084a601ac98ce80a21bed4f63c41a6806aaee11837ddc40e2f4fe91113ceb48592681ac2fe8548a8b5916e85aa266f85b0a77d3d3e9d9ee8418179feccd52045f51567e8152ba106379501d6e44a5f27555dfd81ce0bd1a7fcfa62299bc39017bbbf8c59a41b93d6db75b16b3548d2c76003114118268dd24b42d1f3fd1cdbe0ff1b3c2fd484230ec89d75f80da800717a4557f3de48a0c57e1a78b6b78016664ce591dbb8a27307df01f03ad24d0dc505fec868f59360f6329024b8373a670e61458ed7ef8e329f49959b7dd3919aceb17e65de1dce294f473f70969208a7a0f66c9928a30700d384140a67419af021636f708a033e453cc1ed0d937cbcad6dba09dc23d0488b4b9c5128aff3af8e4c67f4f6b08a247af7e9db54d710871aaea16023de9e4e20a0574286811aae820bd62e3b37c2d61420fd17455aace902f02a7005a9bf5c2ab8e990db75ccb0829a747129f0e06a6f0daf158bdc6fddc35a1ff91e7473d0c796ad68dcaed2903728857af00322bde5516bf749d8475f9c0745b98adfc25295ba8cc3f1ee4bf25416389b1d0efdeddf
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137075);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/08");

  script_cve_id("CVE-2019-1804");
  script_bugtraq_id(108127);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo80686");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190501-nexus9k-sshkey");

  script_name(english:"Cisco Nexus 9000 Series Fabric Switches Application Centric Infrastructure Mode Default SSH Key Vulnerability (cisco-sa-20190501-nexus9k-sshkey)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device version has a default SSH key with root privilages (cisco-sa-20190501-nexus9k-sshkey)");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software for Nexus 9000 Series Fabric Switches ACI Mode has a 
Default SSH System Key. An unauthenticated, remote attacker can exploit this, to gain root privileges. 

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190501-nexus9k-sshkey
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9e3299ff");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo80686");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvo80686");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1804");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device", "Host/aci/system/chassis/summary");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

if ('Nexus' >!< product_info.device || product_info.model !~ '^(90[0-9][0-9])' || empty_or_null(get_kb_item("Host/aci/system/chassis/summary")))
  audit(AUDIT_HOST_NOT, 'affected');

vuln_ranges = [
  {'min_ver' : '0.0', 'fix_ver' : '13.2(6i)'},
  {'min_ver' : '14.0', 'fix_ver' : '14.1(1i)'}
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvo80686'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);