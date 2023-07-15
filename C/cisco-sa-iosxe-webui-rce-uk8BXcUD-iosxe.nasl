#TRUSTED 4e6deab84bb156a1abec839af93f36d27a198b12174f43c5df4fa0db3ddbf9c972413918579ba9307b5979fccf56d88da73d4a0a6c260ae865cc783be2f023f873b7ef1d1153c83fd6ed583da0fff44b3337d1a4610f814f1a3b3f0b6122929cf8221b9ffe2decc0b21bc6fc27f9f95b93b6d10882e90641ad241b7ab19a40939d3e4204312c379479f345ea369eef4673a1cfc36589ebaee66c03b9a24fa5c14c8bf1bba9b00f7f329154ca9b1039ece92368bf4f417a759e8c314a56e09799c154a6d6b346a23581ae8ac6113df5bc0c06f636e55b402e12eb7f4a83dc03966c4295084a0e1e80b6d6011b8187b4e3ee3fa1d9976ea88e41cf2a363f7dd832b224e06d4fc8416214b5a1e73bef07e76adec2bec1c73bdeec822126e3bedecedb3fe0f2e02cb6bdfed37ab2b222c9e2468c597af6cc0e9ccf14e4d5d1b0fc358b167f7d230c7a11215d2813a52be9a9ea93348152cce4390f4386d2b4dabd94361a09a6af82e912ceb13df3cb2bc82acf5f096f713913b0e65137f80df5c61f73a2e99d812d06bb76cd358a53df2adea43f0943bff783e52d018cebc053e715384c4f4ffb794b6518238a00df565500a92f49196b632941bf914abcb894b0162295d7888a636ea812ce8e8399d5e47b0fb5100e59b922b81cc857ba7a89ef1e64b728301550caef79660240c76d33c85934b348dd870288fdaafdc110da1988
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137182);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-3218");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq01125");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxe-webui-rce-uk8BXcUD");
  script_xref(name:"IAVA", value:"2020-A-0239-S");

  script_name(english:"Cisco IOS XE Software Web UI RCE (cisco-sa-iosxe-webui-rce-uk8BXcUD)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by
a remote code execution vulnerability. An authenticated, remote attacker can
exploit this, by supplying improperly validated input, to execute arbitrary
code with root privileges on the underlying Linux shell.

Please see the included Cisco BIDs and Cisco Security Advisory for more
information.

Note that Nessus has not tested for this issue but has instead relied only on
the application's self-reported version number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-webui-rce-uk8BXcUD
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?166cf8b9");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-73388");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq01125");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvq01125
or apply the workaround mentioned in the advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3218");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '16.9.4c',
  '16.9.4',
  '16.9.3s',
  '16.9.3h',
  '16.9.3a',
  '16.9.3',
  '16.9.2s',
  '16.9.2a',
  '16.9.2',
  '16.9.1s',
  '16.9.1d',
  '16.9.1c',
  '16.9.1b',
  '16.9.1a',
  '16.9.1',
  '16.8.3',
  '16.8.2',
  '16.8.1s',
  '16.8.1e',
  '16.8.1d',
  '16.8.1c',
  '16.8.1b',
  '16.8.1a',
  '16.8.1',
  '16.7.4',
  '16.7.3',
  '16.7.2',
  '16.7.1b',
  '16.7.1a',
  '16.7.1',
  '16.6.7a',
  '16.6.7',
  '16.6.6',
  '16.6.5b',
  '16.6.5a',
  '16.6.5',
  '16.6.4s',
  '16.6.4a',
  '16.6.4',
  '16.6.3',
  '16.6.2',
  '16.6.1',
  '16.12.1y',
  '16.11.1s',
  '16.11.1c',
  '16.11.1b',
  '16.11.1a',
  '16.11.1',
  '16.10.2',
  '16.10.1s',
  '16.10.1g',
  '16.10.1f',
  '16.10.1e',
  '16.10.1d',
  '16.10.1c',
  '16.10.1b',
  '16.10.1a',
  '16.10.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['HTTP_Server_iosxe']);
workaround_params = {'no_active_sessions' : 1};

reporting = make_array(
'port'     , product_info['port'], 
'severity' , SECURITY_HOLE,
'version'  , product_info['version'],
'bug_id'   , 'CSCvq01125'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
