#TRUSTED 9720b537506e9c0cad479cba4ee102053812b93029a8edde5ad1e1514cd351f61c40b38aee3a20facee937e8950f2c2a4b5181695a54418f7c3ce8d28f5c6d37e0bba48eb4b8129132c96598fa9f3b49084ef4b412cbfb69ab1c564d73859440d546d3dbc25a8b49ab54713aec106a38a97cdff6dffb55e5b9e2ed66c3340171c837cb351f0bcb0eb127db55852b1e25bca3dc0787f816a34ad96fcd2440396840819caad6dac4574730e49a06cef4a2a1dffc018d5a7bdf397267ffb7d8496ac148bb50e7cde2293e92e29aaf3d3755347e689d14bfee88061350e22329288c4a44940affd6e12858c15d5ec12a002ddc576c89d4cf108b13062e6ba01bdaea16ec10dac7ac599b3a8e8c793e310d3b0384d35359e95dbf191fbdc285e33029c0e47fb4bb129d82a67a7808eec8e374353fcf6bfb570469a4f5b2c8c55424a97b6154fa1ffa672a7d898ebfb63e303f31155a126333fe44cb72f1030f6e5a438a6ee1a9dd89de5d4b8baff5d00c754a67dea1f3a2e717037d154af6235e36f18cc2a660ad78733fdb4478245893e94f409ef46f34441557b27f4f1d5046358bd1ae33fa38130543beb4f007a72651953fd91e134f85b4f8e3cdb2f96ade31627c9f2b69a35cbe0a9796d345e4c591ec49d74e24233b36d98b1df4e35785d77f69e728e9bcd025aa92562d1306b046cfe0603092a4160ac66d4bb3a7276c9ebc
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134115);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/08");

  script_cve_id("CVE-2019-15998");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp91299");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191120-iosxr-ssh-bypass");

  script_name(english:"Cisco IOS XR Software NETCONF Over Secure Shell ACL Bypass (cisco-sa-20191120-iosxr-ssh-bypass)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR Software is affected by a vulnerability in the access-control
logic of the NETCONF over Secure Shell (SSH) due to a missing check in the NETCONF over SSH access control list (ACL).
An unauthenticated, remote attacker can exploit this, by by connecting to an affected device using NETCONF over SSH, in
order to connect to the device on the NETCONF port. Valid credentials are required to access the device. This
vulnerability does not affect connections to the default SSH process on the device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20191120-iosxr-ssh-bypass
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?69c89c54");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp91299");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvp91299");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-15998");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/28");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl", "cisco_enum_smu.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XR');

version_list=make_list('6.5.1', '6.5.2', '6.5.3');

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

smus['6.5.3'] = 'CSCvp91299';

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvp91299'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list,
  router_only:TRUE,
  smus:smus
);
