#TRUSTED 2984e9110faf211108a601ca25d411630e23f1132ece72b6c646e362f508adef98d4ce6cb0defe7be11d864fba6818a4bd142523593d3575b26e8ff981b0151ab4a1271bc21fcd7ab9f9a30320c65ec54a4c1bd3d8876839e380a29a1f5b1809b90e6318215c42b4b61d9d15a1d6536703f831019581a215de1f572a9ca068b92b71c3af9592e940e6922ee181365071e7c39f2dc879431a17ad8472a3a3f3df1f4495908c416dc33f6d32ce0e52b1467222dfb223cb0e46d2e4b2ed8f3616b24412a93472f8aebbd089ea843d2a8ccca8aec5bb55eec66d759d8ce4ec334261bb52725711c6fa7518abd5527e402f4925e35a25942cab04b6c31e7526a49c753c91d26bdbf775b790d718bb16d0927e56c80906ddbeac12d2b8b3a3223cf260485b3d3b779593dff2be965156c97245b17cd55494644a3f3393727a84822d3be9aeb393e2975c86b4f46515746e130eb95af46ab4bd6d0e5af47071238440d79ff7894e7ff1646f91266b6ad76b368423a0227a83fafc5205630281faf02571e2deda16a0e37567f7d1b10b40e38e79ffb222bd665fc52ca46bbc8476548ae0c2a2a9c67ceafd936ce4c24d94d97531cec840f39df5c74ff1701105f03ffc178041028dd94c7c9a33b6f4f49808ac855ad391b70fbda396845e3112a03272f2375953adc7a8860dca30a2d0fa9456ff9c4f0f605b225863377c6b4788b8b053
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(149368);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/12");

  script_cve_id("CVE-2021-1228");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu84576");
  script_xref(name:"CISCO-SA", value:"cisco-sa-n9kaci-unauth-access-5PWzDx2w");

  script_name(english:"Cisco Nexus 9000 Series Fabric Switches ACI Mode Fabric Infrastructure VLAN Unauthorized Access (cisco-sa-n9kaci-unauth-access-5PWzDx2w)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the fabric infrastructure VLAN connection establishment of Cisco Nexus 9000 
Series Fabric Switches in Application Centric Infrastructure (ACI) is affected by unauthorized access vulnerability 
due to insufficient security requirements during the Link Layer Discovery Protocol (LLDP) setup phase of the 
infrastructure VLAN. An unauthenticated, adjacent attacker could exploit this by sending a crafted LLDP packet on the 
adjacent subnet to an affected device. A successful exploit could allow the attacker to connect an unauthorized server 
to the infrastructure VLAN, which is highly privileged. With a connection to the infrastructure VLAN, the attacker can 
make unauthorized connections to Cisco Application Policy Infrastructure Controller (APIC) services or join other host 
endpoints. no workarounds that address this vulnerability.

Please see the included Cisco BID and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-n9kaci-unauth-access-5PWzDx2w
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0064df70");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu84576");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvu84576");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1228");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/11");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/aci/system/chassis/summary", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

if ('Nexus' >!< product_info.device || product_info.model !~ "^[9][0-9]{3}")
  audit(AUDIT_HOST_NOT, 'an affected model');

#  9k in ACI mode
if (empty_or_null(get_kb_list('Host/aci/*')))
    audit(AUDIT_HOST_NOT, 'an affected model due to non ACI mode');

var version_list = make_list(
  '11.0(1b)',
  '11.0(1c)',
  '11.0(1d)',
  '11.0(1e)',
  '11.0(2j)',
  '11.0(2m)',
  '11.0(3f)',
  '11.0(3i)',
  '11.0(3k)',
  '11.0(3n)',
  '11.0(3o)',
  '11.0(4h)',
  '11.0(4o)',
  '11.0(4q)',
  '11.0(4g)',
  '11.1(1j)',
  '11.1(1o)',
  '11.1(1r)',
  '11.1(1s)',
  '11.1(2h)',
  '11.1(2i)',
  '11.1(3f)',
  '11.1(4e)',
  '11.1(4f)',
  '11.1(4g)',
  '11.1(4i)',
  '11.1(4l)',
  '11.1(4m)',
  '11.2(1i)',
  '11.2(2g)',
  '11.2(3c)',
  '11.2(2h)',
  '11.2(2i)',
  '11.2(3e)',
  '11.2(3h)',
  '11.2(3m)',
  '11.2(1k)',
  '11.2(1m)',
  '11.2(2j)',
  '12.0(1m)',
  '12.0(2g)',
  '12.0(1n)',
  '12.0(1o)',
  '12.0(1p)',
  '12.0(1q)',
  '12.0(2h)',
  '12.0(2l)',
  '12.0(2m)',
  '12.0(2n)',
  '12.0(2o)',
  '12.0(2f)',
  '12.0(1r)',
  '12.1(1h)',
  '12.1(2e)',
  '12.1(3g)',
  '12.1(4a)',
  '12.1(1i)',
  '12.1(2g)',
  '12.1(2k)',
  '12.1(3h)',
  '12.1(3j)',
  '12.2(1n)',
  '12.2(2e)',
  '12.2(3j)',
  '12.2(4f)',
  '12.2(4p)',
  '12.2(3p)',
  '12.2(3r)',
  '12.2(3s)',
  '12.2(3t)',
  '12.2(2f)',
  '12.2(2i)',
  '12.2(2j)',
  '12.2(2k)',
  '12.2(2q)',
  '12.2(1o)',
  '12.2(4q)',
  '12.2(4r)',
  '12.2(1k)',
  '12.3(1e)',
  '12.3(1f)',
  '12.3(1i)',
  '12.3(1l)',
  '12.3(1o)',
  '12.3(1p)',
  '13.0(1k)',
  '13.0(2h)',
  '13.0(2k)',
  '13.0(2n)',
  '13.1(1i)',
  '13.1(2m)',
  '13.1(2o)',
  '13.1(2p)',
  '13.1(2q)',
  '13.1(2s)',
  '13.1(2t)',
  '13.1(2u)',
  '13.1(2v)',
  '13.2(1l)',
  '13.2(1m)',
  '13.2(2l)',
  '13.2(2o)',
  '13.2(3i)',
  '13.2(3n)',
  '13.2(3o)',
  '13.2(3r)',
  '13.2(4d)',
  '13.2(4e)',
  '13.2(3j)',
  '13.2(3s)',
  '13.2(5d)',
  '13.2(5e)',
  '13.2(5f)',
  '13.2(6i)',
  '13.2(41d)',
  '13.2(7f)',
  '13.2(7k)',
  '13.2(9b)',
  '13.2(8d)',
  '13.2(9f)',
  '13.2(9h)',
  '11.3(1g)',
  '11.3(2f)',
  '11.3(1h)',
  '11.3(1i)',
  '11.3(2h)',
  '11.3(2i)',
  '11.3(2k)',
  '11.3(1j)',
  '11.3(2j)',
  '14.0(1h)',
  '14.0(2c)',
  '14.0(3d)',
  '14.0(3c)',
  '14.1(1i)',
  '14.1(1j)',
  '14.1(1k)',
  '14.1(1l)',
  '14.1(2g)',
  '14.1(2m)',
  '14.1(2o)',
  '14.1(2s)',
  '14.1(2u)',
  '14.1(2w)',
  '14.1(2x)',
  '14.2(1i)',
  '14.2(1j)',
  '14.2(1l)',
  '14.2(2e)',
  '14.2(2f)',
  '14.2(2g)',
  '14.2(3j)',
  '14.2(3l)',
  '14.2(3n)',
  '14.2(3q)',
  '14.2(4i)',
  '14.2(4k)',
  '14.2(4o)',
  '14.2(4p)',
  '14.2(5k)',
  '15.0(1k)',
  '15.0(1l)',
  '15.0(2e)',
  '15.0(2h)'
);

var reporting = make_array(
  'port'     , 0,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvu84576',
  'disable_caveat', TRUE,
  'severity' , SECURITY_NOTE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
