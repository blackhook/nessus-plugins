#TRUSTED 084c84e1dbf1b0f8e8c43d71d822a301a71134a571ae8c0ee023ebeae555d6005a74306b9cccacd4526c901fd3ec5e0368bf01cce80bbe3413fa7928155137a42ee10222ee0d5bd869a109b071994799987aa68cef1a71eb4ecf2bf5a6f7c567e5f9659a148f623d8ca422c4793fca8edb0f188848abd951657726382c04841f80588fc42fd39f07b64dd3d5a0fe865709a2b780d310c593d1db09cdf58b9dbb4e43f572c04ceb87029523549a33d3f4a012600f53457eb0d890e972e9ec336fd050b36970c404f7b03c07666dd9e4a5561c465db3ee090520f5e7deab08660ba66a9f1ad14b7d45f98d7541d3e06ec5f6ae9ebd2f0afe920ab01935715534045de2537a8bc31618cf82466b336092a41a72143d3b4d4efd0bd6ad39e25e25b917ee681ace1290f56d1f6db7ac2745697d9527fb489add2ea7c64d9573855916ec45cbeebdb591be1cfd1f641275a6d0b5a04c0c274a5071c2b2c55e9df44bfa49775baebabdadffb9a6b8f666bcd1f24067b89003b2aace3b4823243f3e85131dcb7c79e1a02829748c6550bcc1644232dede15e0d8d9305bea77ce82b825be42df38fbead04d58a267df3fca2b1c2e4fcbef8e9920baa2e618352155f18b0fc1bfdf73b4b2575ad40e2e53e160f898f9f240a6bc5b68f2f46452ddbee15296a382af8c43f1856baeec051208b867b972b19a9c6ba7d697052c167e2629f603
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(128418);
  script_version("1.6");
  script_cvs_date("Date: 2019/12/20");

  script_cve_id("CVE-2019-1779");
  script_bugtraq_id(108394);
  script_xref(name:"CISCO-BUG-ID", value:"CSCve51688");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh76126");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj00412");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj00416");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190515-nxos-fxos-cmdinj-1779");
  script_xref(name:"IAVA", value:"2019-A-0173");

  script_name(english:"Cisco NX-OS Software Command Injection Vulnerability (CVE-2019-1779)");
  script_summary(english:"Checks the version of Cisco NX-OS Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by the vulnerability that allows an 
authenticated, local attacker to execute arbitrary commands on the underlying operating system of an affected device
with elevated privileges. The vulnerability is due to insufficient validation of arguments passed to certain CLI
commands. An attacker could exploit this vulnerability by including malicious input as the argument of an affected
command. A successful exploit could allow the attacker to execute arbitrary commands on the underlying operating
system with elevated privileges. An attacker would need valid device credentials to exploit this vulnerability.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190515-nxos-fxos-cmdinj-1779
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?29bf8784");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve51688");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh76126");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj00412");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj00416");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCve51688, CSCvh76126, CSCvj00412, and CSCvj00416");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1779");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(77);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/02");

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

cbi = '';

if ('MDS' >< product_info.device && product_info.model =~ '^90[0-9][0-9]')
  cbi = 'CSCve51688';
else if ('Nexus' >< product_info.device)
{
  if (product_info.model =~ '^(3[05]|90)[0-9][0-9]')
    cbi = 'CSCvh76126';
  else if (product_info.model =~ '^(36|95)[0-9][0-9]')
    cbi = 'CSCvj00412';
  else if (product_info.model =~ '^(5[56]|60)[0-9][0-9]')
    cbi = 'CSCvj00416';
  else if (product_info.model =~ '^7[70][0-9][0-9]')
    cbi = 'CSCve51688';
  else audit(AUDIT_HOST_NOT, 'affected');
}
else audit(AUDIT_HOST_NOT, 'affected');

version_list=make_list(
  '8.1(1a)',
  '8.1(1)',
  '7.0(3)I7(5a)',
  '7.0(3)I7(3)',
  '7.0(3)I7(2)',
  '7.0(3)I7(1)',
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
  '7.0(3)F3(4)',
  '7.0(3)F3(3c)',
  '7.0(3)F3(3b)',
  '7.0(3)F3(3a)',
  '7.0(3)F3(3)',
  '7.0(3)F3(2)',
  '7.0(3)F3(1)',
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
  '6.2(1)'
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , cbi
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list,
  switch_only:TRUE
);
