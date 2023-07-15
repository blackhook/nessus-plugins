#TRUSTED 86b456219d0b7c84311d215c63af1766e1dc3fe4e4a9386dee540618a529333e5043018e9e72def86c094739175c1cc3762b68c85c7724bab9682033cea8c7a9072ce107d9308f0fa0d0c1cf892a9a23d32ed184f7896904231ede238ef0af8d4e6cc5495af2b98cfe1b85c5784bd34ecf7ec2c46638f52bef68cda10f063df5f2faf8e9f2158ab5b9de0a0d2251a80f05244e592d0a2f3a6bec22cef4e670e5079b7b19ac41da51b7fa4f408c769efa783d3ebb4a006baf97c7e840d6ebf553c39a36cd77f04549fadbfd73b783eec8ebcf69d6c7107b53de7ae07b6b25f0800c08bef8e841934e948a4b2e9b4728d03b9db6835512f9a12ad8c3ecd7c548aba88e756d6387d3b86af88bac1881405db0a4f59ffc0526d3a4f505e35462a3575c6e99e4d6a5b42cfe296746cb7952d5c109477d54d236b72d0e1d3acff306bf8977593d444ec1f7f645891d24931e12c1cfb01a5ae0d7545e558b65c1e187f893aa6709f0f304d5d641eadb1bb75095243137b266f80b5b97ab110e4d595f6dee2aea91b5cfd691eeaf0b58dd59367d77e53c4ee9db3ba672b2577323973a9af9c3ee05e055b2e92a808c3b6ead104a754dec3eeb8130aa08bbf365ec2e33f6faa7e623d7cde38f143e154ece660cefc7432d6b49070506a832436a09d809c9a223b4c6365da1a8b490c59d71d42c7d07bb3d206ec527027d00b0d1753590ab
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(131131);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/29");

  script_cve_id("CVE-2017-6664");
  script_bugtraq_id(99986);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd22328");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170726-anicrl");

  script_name(english:"Cisco IOS XE Software Autonomic Networking Infrastructure Certificate Revocation (cisco-sa-20170726-anicrl)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a vulnerability in the Autonomic
Networking feature because the affected software does not transfer certificate revocation lists (CRLs) across Autonomic
Control Plane (ACP) channels. An unauthenticated, remote attacker can exploit this, by connecting an autonomic node
that has a known and revoked certificate to the autonomic domain of an affected system. The attacker can then insert a
previously trusted autonomic node into the autonomic domain of an affected system after the certificate for the node
has been revoked.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170726-anicrl
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?21f85a5a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd22328");
  script_set_attribute(attribute:"solution", value:
"No fixes are available for this vulnerability. For more information, see Cisco bug ID CSCvd22328");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6664");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '16.1.2',
  '16.1.3',
  '16.2.1',
  '16.2.2',
  '16.3.1',
  '16.3.2',
  '16.3.3',
  '16.3.1a',
  '16.3.4',
  '16.3.5',
  '16.3.5b',
  '16.3.6',
  '16.3.7',
  '16.3.8',
  '16.3.9',
  '16.4.1',
  '16.4.2',
  '16.4.3',
  '16.5.1',
  '16.5.1a',
  '16.5.1b',
  '16.5.2',
  '16.5.3',
  '3.18.3bSP',
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.6.4',
  '16.6.5',
  '16.6.4a',
  '16.6.5a',
  '16.6.6',
  '16.6.5b',
  '16.6.7',
  '16.6.7a',
  '16.7.1',
  '16.7.2',
  '16.7.3',
  '16.8.1',
  '16.8.1a',
  '16.8.1b',
  '16.8.1s',
  '16.8.1c',
  '16.8.2',
  '16.8.3',
  '16.9.1',
  '16.9.1a',
  '16.9.1s',
  '16.9.3',
  '16.9.2a',
  '16.9.2s',
  '16.9.3h',
  '16.9.4',
  '16.9.3s',
  '16.9.3a',
  '16.9.4c',
  '16.10.1',
  '16.10.1a',
  '16.10.1b',
  '16.10.1s',
  '16.10.1e',
  '16.10.2',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.2',
  '16.11.1s',
  '16.11.1c',
  '16.12.1',
  '16.12.1s',
  '16.12.1a',
  '16.12.1c',
  '16.12.2',
  '17.2.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['autonomic_networking'];

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvd22328',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
    product_info:product_info,
    workarounds:workarounds,
    workaround_params:workaround_params,
    reporting:reporting,
    vuln_versions:version_list
);
