#TRUSTED a0b4498b467c9f52e9c56be49f05c3ee39ccdcfb70237d8d6483ee28146bd0209f71bbeeb44b4f455906c98948ac52e5bbea677f66599979a9272e66c95ed7e08a0ed01aac93935d33b63717b7da23712cbcfb7a261384cbac5517fe54370929c2574da99b58bbe811f29c8131cf0ff2fee0c8a54d8ab2f5b20685f8b8e46d0135c550e0bb543018429b95b6e298a6411734fba56018d2fd3a6131e7006fb4ac6da3e71b3482de46894ddb15511ad53b21135400bc8a167af4d52ddb71b5de70e172471191553766301f35b702f184e2765760eb77a26585617d529d397b8afe6212b87d6bbccc314f71388ddc455725184466e8cac4f56c50bf45644b01cd6b3ef13c158455bfdc7abf24e967efa37b0b982d69925c40d34072abf9870d790b5374e1b0a5fd42218d7d008996bf68ee8a9b3d68e28d730eb270e34b9e4a5bf37a03eb876323c6ee4d6372c70bad255bf2234233d8cb32f4c4fb5778ecd8e899be624e3db459db29552c75d21162b259b236d82b8d528ed3056d7a42c2d1ceeadd5ff6b081bdce33a0ee5644b93d725caeea4d746936bf5fce74d55fcdad8a8e3696b764c63cae6d06342d8388e38ab4715976bd916e6bf1068d7ab31ed7f69999f09e55e99b128e483220f09dbd2821c0c4c3e5bb0cf4d5e90282c6c3a8bd93887e0d422e4f6597340ab3f3dc116f68c2ff786584a91d38ed2724baa9d2d263
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136483);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/19");

  script_cve_id("CVE-2019-1732");
  script_bugtraq_id(108361);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi01453");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj00550");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190515-nxos-rpm-injec");
  script_xref(name:"IAVA", value:"2019-A-0173");

  script_name(english:"Cisco NX-OS Software Remote Package Manager Command Injection Vulnerability (cisco-sa-20190515-nxos-rpm-injec)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is
affected by following vulnerability

  - A vulnerability in the Remote Package Manager (RPM)
    subsystem of Cisco NX-OS Software could allow an
    authenticated, local attacker with administrator
    credentials to leverage a time-of-check, time-of-use
    (TOCTOU) race condition to corrupt local variables,
    which could lead to arbitrary command injection.The
    vulnerability is due to the lack of a proper locking
    mechanism on critical variables that need to stay static
    until used. An attacker could exploit this vulnerability
    by authenticating to an affected device and issuing a
    set of RPM-related CLI commands. A successful exploit
    could allow the attacker to perform arbitrary command
    injection. The attacker would need administrator
    credentials for the targeted device. (CVE-2019-1732)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190515-nxos-rpm-injec
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?60278125");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi01453");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj00550");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs
  - CSCvi01453
  - CSCvj00550");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1732");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/12");

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

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:"Cisco NX-OS Software");

cbi = '';
if('Nexus' >< product_info.device)
{if(product_info.model =~ '^(3[05][0-9][0-9]|90[0-9][0-9])')
    cbi = 'CSCvi01453';
  else if (product_info.model =~ '^(36|95)[0-9][0-9]')
    cbi = 'CSCvj00550';
  else audit(AUDIT_HOST_NOT, 'affected');
}
else audit(AUDIT_HOST_NOT, 'affected');

version_list=make_list(
  '7.0(3)I7(5a)',
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
  '7.0(0)N1(1)',
  '6.0(4)',
  '6.0(3)',
  '6.0(2)A8(9)',
  '6.0(2)A8(8)',
  '6.0(2)A8(7b)',
  '6.0(2)A8(7a)',
  '6.0(2)A8(7)',
  '6.0(2)A8(6)',
  '6.0(2)A8(5)',
  '6.0(2)A8(4a)',
  '6.0(2)A8(4)',
  '6.0(2)A8(3)',
  '6.0(2)A8(2)',
  '6.0(2)A8(1)',
  '6.0(2)A7(2a)',
  '6.0(2)A7(2)',
  '6.0(2)A7(1a)',
  '6.0(2)A7(1)',
  '6.0(2)A6(8)',
  '6.0(2)A6(7)',
  '6.0(2)A6(6)',
  '6.0(2)A6(5b)',
  '6.0(2)A6(5a)',
  '6.0(2)A6(5)',
  '6.0(2)A6(4a)',
  '6.0(2)A6(4)',
  '6.0(2)A6(3a)',
  '6.0(2)A6(3)',
  '6.0(2)A6(2a)',
  '6.0(2)A6(2)',
  '6.0(2)A6(1a)',
  '6.0(2)A6(1)',
  '6.0(2)A4(6)',
  '6.0(2)A4(5)',
  '6.0(2)A4(4)',
  '6.0(2)A4(3)',
  '6.0(2)A4(2)',
  '6.0(2)A4(1)',
  '6.0(2)A3(4)',
  '6.0(2)A3(2)',
  '6.0(2)A3(1)',
  '6.0(2)A1(2d)',
  '6.0(2)A1(1f)',
  '6.0(2)A1(1e)',
  '6.0(2)A1(1d)',
  '6.0(2)A1(1c)',
  '6.0(2)A1(1b)',
  '6.0(2)A1(1a)',
  '6.0(2)A1(1)',
  '6.0(2)',
  '6.0(1)'
);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , cbi,
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info, 
  reporting:reporting, 
  vuln_versions:version_list
);