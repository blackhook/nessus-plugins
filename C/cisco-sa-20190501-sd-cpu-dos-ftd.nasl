#TRUSTED 162318c28e0e43f82961eec56e3f7bfd1d5e334cdc867d1cfe7c3ba0bbc9f6277316d045698faeeb74d5b3ff9148c325f15eea60827e91f51ebb31f89df58ac10386eaa2430ba1b450ea104ce3723a013404977c8e43a39b759dffe73996d000b43f42507bc50be0e04acedb2b07620b1ff1dce7dd381f364ec5de95eb1b354ca898dc7390eb3f0bb7198788700b21596a6abd86e1dcc1a476dbc621ef0c205137cf2de2307b8878d43d55a4f3e6ddeb799b8e8bab49e1a99ded87edfd782fbaffadd5f62dc5765ca7a35a64ca50b83110cf0d198d098fed6e3ed8d77f9cb695b151f0d1b7f7479e499c21b4014e6e4e2f349f35e68571a8815d834106d19e937516c0d9d406a45154b6198df6363667f2d8218468c9f1efcb6b71f237b7037a916ea3b6cb67f8b4e48b74fa22bfd5511256e7464fd2a61b88f31acb52d8a73deb542597a06b044c032805488ff619968ee77db41c21e625fa6189992d81c6d5114420c9ca58e96bd53be4c5ee82c33d93ec97e35812d2a9aeaf68136d7318becbe84471c223fce96d40bdfe3f44a214a8f0eb7ab7f68f46e818bbafb06e4735986c0412486ad80b52c3dd6bba3bc4a9fb6a0cb906b0e60cb2d5dd09fcfafc18bb4cec00e8f233a7480df8c5a09943cddec29392085e6e8109b61f2fbcdb4551f9da559002e88c9714d64d2b8d9e044d0cd7608d42ecb5f57066d76beee361b4
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136971);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/12");

  script_cve_id("CVE-2018-15388");
  script_bugtraq_id(108137);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj33780");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190501-sd-cpu-dos");

  script_name(english:"Cisco Firepower Threat Defense WebVPN DoS (cisco-sa-20190501-sd-cpu-dos)");

  script_set_attribute(attribute:"synopsis", value:
"The packet inspection software installed on the remote host is
affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Firepower Threat Defense (FTD) software installed on the remote host
is affected by a vulnerability in the WebVPN login process that allows an unauthenticated, remote attacker to cause
increased CPU utilization on an affected device. The vulnerability is due to excessive processing load for existing
WebVPN login operations. An attacker can exploit this vulnerability by sending multiple WebVPN login requests to the
device. A successful exploit could allow the attacker to increase CPU load on the device, resulting in a denial of
service (DoS) condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190501-sd-cpu-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ba7b5af9");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj33780");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvj33780");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15388");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(400);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense", "Host/Cisco/Firepower");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');
model = toupper(product_info.model);

if (
  model !~ '1000V' && # 1000V
  model !~ '30[0-9][0-9]($|[^0-9])' && # ISA 3000
  model !~ '5505($|[^0-9])' && # 5505
  model !~ '55[0-9][0-9]-X' && # 5500-X
  model !~ '65[0-9][0-9]($|[^0-9])' && # 6500
  model !~ '76[0-9][0-9]($|[^0-9])' && # 7600
  model !~ '21[0-9][0-9]($|[^0-9])' && # Firepower 2100 SSA
  model !~ '41[0-9][0-9]($|[^0-9])' && # Firepower 4100 SA
  model !~ '93[0-9][0-9]($|[^0-9])' && # Firepower 9300 ASA
  model != 'v' # ASA
) audit(AUDIT_HOST_NOT, "an affected Cisco FTD product");

is_ftd_cli = get_kb_item_or_exit("Host/Cisco/Firepower/is_ftd_cli");
if (!is_ftd_cli)
{
  if (report_paranoia < 2)
    audit(AUDIT_PARANOID);
  else
  {
    workarounds = make_list();
    extra = 'Note that Nessus was unable to check for workarounds';
  }
}
else
{
  workarounds = make_list(CISCO_WORKAROUNDS['ssl_vpn']);
  cmds = make_list('show running-config');
}

vuln_ranges = [
  {'min_ver' : '6.0', 'fix_ver' : '6.2.3.12'}
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvj33780',
  'extra'    , extra
);

if (max_index(cmds) > 0)
  reporting['cmds'] = cmds;

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  workarounds:workarounds
);
