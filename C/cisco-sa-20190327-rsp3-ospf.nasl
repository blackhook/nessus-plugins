#TRUSTED a9ea3a92da383dab1fa1e0d3b5da699d59782a30ced54c90f7dddb5e42cbbfe5f6a1d3fdce082bb4c18dd44600ac9a85e64e72fd834a9f428c7672d7306c557e79e6441881ac3146aa8ea493b87b0790b97c325b98b7e43d12d1e5b13286ac971d3ec35423ef13560308ca0f36b05da16c943a7dee0edd2f6a4af48891cce6d90567e685a2906fc936f6978520ca2bee5ffa50a9822c0ac385f4d358655c3a2c570c63efc9372919a57416feaf071511d9fe908eda4059055ed13b135e9818db35993c75b11afc8861a67c24cd8383bd8fec39dd209308c70d8682309f58dbc032238beb114a4ca969c3280e5dd00bcefa9185a7d88092ad4f368cc9bc179b8ca1625689ce5736248c48d1d21f1f5bb3d47646b51486fb9d473c80d82eb2c664c69236174297f22fb9d74b21f7a5900aac2edb18fc1548e6c7f512e4b9a3fc09aa05bf05442e45ee78cddf42f5b3c1a767ae3668b9bca9d7bd2e1dc307c87836561f9166928903c9f477f05637ad3c5ba94eff9261151316ef0eba78dca6de680649e01ad52f18ce318fafbaf47593b9af0e2e24597cd5b6ddd23a93cc04967059c913b60adae6419485500c468319e7d32d194b99b5646a4a20d36c8162be94e138f6aabcf543a5e96d489f5a362f348c5a0878fd85ca2149f894ac0e9401a2a38b9066bdf495483b74537c2746070729c17b55807ab83d29178238e3520472
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134894);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id("CVE-2019-1749");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh06656");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190327-rsp3-ospf");

  script_name(english:"Cisco Aggregation Services Router 900 Route Switch Processor 3 OSPFv2 DoS (cisco-sa-20190327-rsp3-ospf)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a vulnerability in the ingress traffic
validation for Cisco Aggregation Services Router (ASR) 900 Route Switch Processor 3 (RSP3) due to insufficient
validation of ingress traffic on the ASIC used on the RSP3 platform. An unauthenticated, adjacent attacker can exploit
this, by sending a malformed OSPF version 2 (OSPFv2) message, in order to trigger a reload and cause a denial of service
(DoS) condition on the affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190327-rsp3-ospf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5f440371");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-71135");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh06656");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvh06656");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1749");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/25");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model", "Settings/ParanoidReport");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

model = toupper(product_info['model']);
if (model !~ 'ASR90[0-9]([^0-9]|$)')
  audit(AUDIT_HOST_NOT, 'an affected model');

version_list=make_list(
  '3.13.6aS',
  '3.16.0aS',
  '3.16.1aS',
  '3.16.2aS',
  '3.16.3aS',
  '3.16.4S',
  '3.16.4bS',
  '3.16.4gS',
  '3.16.5S',
  '3.16.4cS',
  '3.16.4dS',
  '3.16.4eS',
  '3.16.6S',
  '3.16.5aS',
  '3.16.7S',
  '3.16.6bS',
  '3.16.7bS',
  '3.16.8S',
  '3.17.0S',
  '3.17.1S',
  '3.17.2S',
  '3.17.3S',
  '3.17.4S',
  '16.5.1',
  '16.5.2',
  '16.5.3',
  '3.18.0S',
  '3.18.1S',
  '3.18.2S',
  '3.18.3S',
  '3.18.4S',
  '3.18.0SP',
  '3.18.1SP',
  '3.18.1gSP',
  '3.18.1bSP',
  '3.18.2SP',
  '3.18.1hSP',
  '3.18.1iSP',
  '3.18.3SP',
  '3.18.4SP',
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.6.4',
  '16.7.1',
  '16.7.2',
  '16.8.1',
  '16.8.1b',
  '16.8.1c'
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();


reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvh06656'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list,
  router_only:TRUE
);
