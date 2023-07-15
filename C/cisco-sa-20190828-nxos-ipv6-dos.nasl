#TRUSTED 32434ef62c923b01225ece22bcd1d67474c5f7b296e5439c2ab02ce8c0e79fabee5c035124974f5848875330537839dc392574ff9b0be5fb775241ef6914bab66432079a6f8c760ada651823e637a5607af7f99d048bff2534dc2640be4c107ed0a208adf3dea62256aa824fc03653a443c997b75655773f47ff5041b543c85f0ffa90d609bccd894e6ccd0f16e0140580aece2cb6c2812b8765b850c2bf6f6981e2bed4af330dac72061b5acfe20cdc09c0c8c3d84bfbf13a5ba9e3abef3906a3a42c9cb845af9d78d7292a6d9bb2652b707beabd6d16adeb8a5d99668b6480712dcb1a731d69ade9b3e232f4570f23087771ed4c74888b880040cc5fba568691517f41308f2b9213a3dede392fd9b2fe1a6180c83303657a219e76af0218e624597e1ffc73f1402bc40508d03a36b3f677e2fa88175b681be7ac5acd2f1d4ac531eed6aa6cee3e93f0543aca2348f757c71ab9edce67e07e670c32c23e89f38bbcc81ad53e5ef35652444d181d9a4e8ae6476e17a56c01976388e5dfcec0ce501de356424f6cbb5d1511511c12005c29bc86805c91a1d99d451edfd7bf3acb41d3e2793dacb1648b368ed56063a8082f6039e5ee6e4b33328ed24711b37b1688482671ea0d250dc96d9c1ff901328ce65e944e83c26a36db27c43e6cd952dd15aacb88c41b81efe8bfd9ae3cbf064ea3d2e14325db5918d199c9f17b42df50
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(132772);
  script_version("1.4");
  script_cvs_date("Date: 2020/01/13");

  script_cve_id("CVE-2019-1964");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvn46719");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190828-nxos-ipv6-dos");
  script_xref(name:"IAVA", value:"2019-A-0317");

  script_name(english:"Cisco NX-OS Software IPv6 Denial of Service Vulnerability (cisco-sa-20190828-nxos-ipv6-dos)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by a denial of service (DoS) vulnerability in
its IPV6 packet processing component due to insufficient validation. An unauthenticated, remote attacker can exploit 
this issue, by sending malformed IPV6 packets to an affected device, to force a restart of the system.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190828-nxos-ipv6-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?90ba471c");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvn46719");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID 
  CSCvn46719");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1964");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/10");

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

if ('Nexus' >!< product_info.device || product_info.model !~ '^7[07][0-9][0-9]')
  audit(AUDIT_HOST_NOT, 'affected');

version_list = make_list(
  '8.1(1)',
  '8.1(2)',
  '8.1(2a)',
  '8.2(1)',
  '8.2(2)',
  '8.3(1)',
  '8.3(2)'
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info.version,
  'bug_id'   , 'CSCvn46719'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
