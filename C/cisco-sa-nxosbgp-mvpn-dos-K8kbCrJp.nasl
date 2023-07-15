#TRUSTED 346fad6216c6f52e0571615b8b7b8e659fbab86f95b944ca6a7fd7c972bd4ca2a866f886d2eb019281be2ab355308edee80b59e3e70cd99483bf13b56ce04be5ebcf473ecefe812d74608c35092add8fafed9020b999768f8af4d00eafeefe925fa2cf9f7de04c53f5f1a7368da5bdc0922d8e3c3f44b19594503ce90a484334adc51c98f0521446d74b6a56375bd7e0e95bd9b6362d68dd0ea33a579f9b260759129299f50516df4bba093d7b7ebbf6c58935c2e0e3312ac1db72fc43b767faabb760a72edd2156c5d3bb3b65a17ab28a49b4f5cab779874f490e94e3c673d58a542b6870cc368137032bd7ead31dee957e27e74e0baea59f2d36216dae0b40f15efe9aea496095811d912eeaae10f0b14d1331c3069372a169be7fe428b1f23cf38fae285c177d7650dee71a2aa80cf337c3995bbbe063a35629e65bc43f995ada9d102d6d75267958bc29ca5de8dc36b9f8e58fd3f61233bb387f07c00bea6f4aa80983c5051738514981c56830642e902935ada224566bf93af25c26cd243bf495fbef8cc4b43729a799a3d0f7cbf704f87d18bb5be5f4a0f24659b4c65c247f8c31819d9ec1b726bfacca31a0900dc7faa83572542cefcab71cd53bd5a1ae60a1fab4fcfbc71c09a338566678fd2274e2b83acdf4d28bc79437ce8b8679542dd280ac5a709ebfd784f2f1bc57d51e8f59c544f04b2da4caf4f133fe91a5
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140131);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/04");

  script_cve_id("CVE-2020-3398");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr60479");
  script_xref(name:"CISCO-SA", value:"cisco-sa-nxosbgp-mvpn-dos-K8kbCrJp");
  script_xref(name:"IAVA", value:"2020-A-0394");

  script_name(english:"Cisco NX-OS Software Border Gateway Protocol Multicast VPN Session DoS (cisco-sa-nxosbgp-mvpn-dos-K8kbCrJp)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by a vulnerability in the Border Gateway
Protocol (BVP) Multicast VPN (MVPN) implementation due to incorrect parsing of a specific type of BGP MVPN update
message. An unauthenticated, remote attacker can exploit this, by sending this BGP MVPN update message, in order to
cause a partial denial of service (DoS) condition due to the BGP session being down.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxosbgp-mvpn-dos-K8kbCrJp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?07d34ac4");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74239");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr60479");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvr60479");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3398");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/02");

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

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

if ('Nexus' >!< product_info.device || product_info.model !~ "^[379][0-9]{3}")
  audit(AUDIT_HOST_NOT, 'an affected model');

#  not 9k in ACI mode
if (!(empty_or_null(get_kb_list('Host/aci/*'))))
    audit(AUDIT_HOST_NOT, 'an affected model due to ACI mode');

version_list=make_list(
  '7.0(3)F3(1)',
  '7.0(3)F3(2)',
  '7.0(3)F3(3)',
  '7.0(3)F3(3a)',
  '7.0(3)F3(3c)',
  '7.0(3)F3(4)',
  '7.0(3)F3(5)',
  '7.0(3)I7(1)',
  '7.0(3)I7(2)',
  '7.0(3)I7(3)',
  '7.0(3)I7(3z)',
  '7.0(3)I7(4)',
  '7.0(3)I7(5)',
  '7.0(3)I7(5a)',
  '7.0(3)I7(6)',
  '7.0(3)I7(6z)',
  '7.0(3)I7(7)',
  '7.0(3)IA7(1)',
  '7.0(3)IA7(2)',
  '7.0(3)IM7(2)',
  '8.3(1)',
  '8.3(2)',
  '8.4(1)',
  '9.2(1)',
  '9.2(2)',
  '9.2(2t)',
  '9.2(2v)',
  '9.2(3)',
  '9.2(3y)',
  '9.2(4)',
  '9.3(1)',
  '9.3(1z)',
  '9.3(2)'
);

workarounds = make_list(CISCO_WORKAROUNDS['show_running-config']);
workaround_params = {'pat':make_list('address-family ipv(4|6) mvpn', 'feature ngmvpn'), 'require_all_patterns':TRUE};

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr60479',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list,
  workarounds:workarounds,
  workaround_params:workaround_params
);



