#TRUSTED 2aa3174aea69719a67fe03e7ea3757e54d2c191daa5a25d1f951ac79927139d4f2796e19c76ba7d8b4300f188dacaa35f14cdb3bfc81565e092964b0dc8e0a072f9c0f6d26efbac7c726df203c811340b7016ce4257aec7ecbdb5af6dfb03857ea74e21b000bb716a74aec1094e05752a825f76491284ec1a85037f716e52b40b9102b592cd116ac52f39f44e0494010db768186644b351bb2f5894570b31b4896792eec66c3de3a2159ef28f0914d3f5e730e75082f58d1f561ca5b0615f62d66f463da524da53c3f933846e92e0393377131d533712fe8bcf315a2ab7db0201c31bbc3cdb24980496ce0e6346da78ce1b75832cf02e281b2e79602d87da7f2b3bb9781ef981883a1951cdd0322c544d91d41128b55ede7e2b565955b8c26d7d91df9c2b7c9a7d91c99f7b4ad2c0b751c0175277f1ecdebc127449a58d440afb2fc1438c3a2d8fc3b56abfc087b8e9f48e733cfd4c839b29574f2e8b183bcb389d2f1288409e0db3f5e1b72f0a88b22b4d9923da3b436dfcc2b7f95276889cf5b30ea1c4c94887cc861bfeef649567df5549cb544560fd9fbbdbcfa1e48469a0565b4dc7eb60762d41ec5f1a0eaffa7242aaebb5e79e29bd119d94f7ed3642d0d8e5a301c666b494d5afbbc6e0a768cf21ec0a563b375830e7b6babec506f4545893d459719ec4ceb11b70a1c40b98a44510da0fb4443e6d0a72c2a21441d97
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125776);
  script_version("1.6");
  script_cvs_date("Date: 2019/12/20");

  script_cve_id("CVE-2019-1808");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi42248");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190515-nxos-spsv");
  script_xref(name:"IAVA", value:"2019-A-0180");

  script_name(english:"Cisco MDS 9700 Series Multilayer Directors and Nexus 7000/7700 Series Switches Software Patch Signature Verification Vulnerability");
  script_summary(english:"Checks the version of Cisco NX-OS Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by a vulnerability in the Image Signature
Verification feature of Cisco NX-OS Software could allow an authenticated, local attacker with administrator-level
credentials to install a malicious software patch on an affected device. The vulnerability is due to improper
verification of digital signatures for patch images. An attacker could exploit this vulnerability by loading an unsigned
software patch on an affected device. A successful exploit could allow the attacker to boot a malicious software patch
image.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190515-nxos-spsv
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9ec96abf");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi42248");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvi42248");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1808");
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

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

if ( (product_info.device == 'MDS' && product_info.model !~ '^97[0-9][0-9]') ||
     (product_info.device == 'Nexus' && product_info.model !~ '^7[07][0-9][0-9]') )
  audit(AUDIT_HOST_NOT, 'affected');

version_list=make_list(
  '8.2(2)',
  '8.2(1)',
  '7.3(2)N1(1)',
  '7.3(2)N1(0.296)',
  '7.3(2)D1(3a)',
  '7.3(2)D1(3)',
  '7.3(2)D1(2)',
  '7.3(2)D1(1A)',
  '7.3(2)D1(1)',
  '7.3(1)N1(1)',
  '7.3(1)N1(0.1)',
  '7.3(1)DY(1)',
  '7.3(1)D1(1B)',
  '7.3(1)D1(1)',
  '7.3(0.2)',
  '7.3(0)N1(1b)',
  '7.3(0)N1(1a)',
  '7.3(0)N1(1)',
  '7.3(0)DY(1)',
  '7.3(0)DX(1)',
  '7.3(0)D1(1)',
  '7.2(2)D1(2)',
  '7.2(2)D1(1)',
  '7.2(1)N1(1)',
  '7.2(1)D1(1)',
  '7.2(0)ZZ(99.1)',
  '7.2(0)N1(1)',
  '7.2(0)D1(1)',
  '7.2(0)D1(0.437)',
  '7.1(5)N1(1b)',
  '7.1(5)N1(1)',
  '7.1(4)N1(1e)',
  '7.1(4)N1(1d)',
  '7.1(4)N1(1c)',
  '7.1(4)N1(1a)',
  '7.1(4)N1(1)',
  '7.1(3)N1(5)',
  '7.1(3)N1(4)',
  '7.1(3)N1(3.12)',
  '7.1(3)N1(3)',
  '7.1(3)N1(2a)',
  '7.1(3)N1(2.1)',
  '7.1(3)N1(2)',
  '7.1(3)N1(1b)',
  '7.1(3)N1(1)',
  '7.1(2)N1(1a)',
  '7.1(2)N1(1)',
  '7.1(1)N1(1a)',
  '7.1(1)N1(1)',
  '7.1(0)N1(2)',
  '7.1(0)N1(1b)',
  '7.1(0)N1(1a)',
  '7.1(0)N1(1)',
  '7.0(8)N1(1a)',
  '7.0(8)N1(1)',
  '7.0(7)N1(1b)',
  '7.0(7)N1(1a)',
  '7.0(7)N1(1)',
  '7.0(6)N1(4s)',
  '7.0(6)N1(3s)',
  '7.0(6)N1(2s)',
  '7.0(6)N1(1c)',
  '7.0(6)N1(1)',
  '7.0(5)N1(1a)',
  '7.0(5)N1(1)',
  '7.0(4)N1(1a)',
  '7.0(4)N1(1)',
  '7.0(3)N1(1)',
  '7.0(3)IX1(2a)',
  '7.0(3)IX1(2)',
  '7.0(3)I7(5a)',
  '7.0(3)I7(5)',
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
  '7.0(0)N1(1)'
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();


reporting = make_array(
'port'     , 0,
'severity' , SECURITY_NOTE,
'version'  , product_info['version'],
'bug_id'   , 'CSCvi42248'
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
