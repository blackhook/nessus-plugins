#TRUSTED 19c795a53142466ed0a5b50dcc0dca7f4f0f7986c384af62fb712a28e6fd7d321f00c92f1e54b614c426bb4a83f8927b869951af12fae2a725317c2da346dadd7136b118f72c071bc312660b9d5cc79b2c86656002de2373cc39a373577771794dfd6f53a8d9bbb478f5d22eed0ad8655ffa7bfd29669316536c57fba61a734e186ed8fa7bf584ddb6831efe22e84c4099be9ff1a0b123fac3680affd6c395bdc1506b90b4652fde40fb1a278b3d3f75341bf3ee902045140efe76a08e1a041a4c3a17884ff00e83a14f64e8860cb28a84c13122e221850b60ec8417ca3a9555712404bec6ff85bdd0678a36cfa86f9ccdd21eb73236dfde8afd1f81e90dd3a930bfd1d1221a864a8568b50cac31d8f7ebbb4177bf28666853f9d4e702193f69779bec206936a0b599b67005c0e26813488abf9c53816945242ca9004971a24cbf353cd26fabebe5f6498d081e2d8b38bb9909eb4f0e77465ba8b923d1ec6729e4bfe010d0d4a6a428a4808fbcf39adcabe8f263fb8934ca88ff8f57e52e9070fa0b70d7181bbfb774c3d64b6879e18e8696266be694712cad1dd0d6548d04fdb9451f72663f5dd527467db01c2fc48de3baed20e43a03a0dfc55565524be1286a724dc880ccd382a570ea5d8d5871e73e0ad3d89fb75fe56fc00e7ed4269e600731e5b1db14538ad04c716e4e281516ca86458a09f6f2aafb6a08c8eac6d824
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(132044);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id("CVE-2018-15368");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuw45594");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180926-privesc");
  script_xref(name:"IAVA", value:"2019-A-0264");

  script_name(english:"Cisco IOS XE Software Privileged EXEC Mode Root Shell Access (cisco-sa-20180926-privesc)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a vulnerability in the CLI parser due to
the affected software improperly sanitizing command arguments to prevent modifications to the underlying Linux
file system on a device. An authenticated, local attacker who has privileged EXEC mode (privilege level 15) access can
exploit this by executing CLI commands that contain crafted arguments in order to gain access to the underlying Linux
shell of the affected device and execute arbitrary commands with root privileges.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180926-privesc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?06dfb1b7");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuw45594");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCuw45594.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15368");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
  '3.7.0S',
  '3.7.1S',
  '3.7.2S',
  '3.7.3S',
  '3.7.4S',
  '3.7.5S',
  '3.7.6S',
  '3.7.7S',
  '3.7.8S',
  '3.7.4aS',
  '3.7.2tS',
  '3.7.0bS',
  '3.7.1aS',
  '3.8.0S',
  '3.8.1S',
  '3.8.2S',
  '3.9.1S',
  '3.9.0S',
  '3.9.2S',
  '3.9.1aS',
  '3.9.0aS',
  '3.10.0S',
  '3.10.1S',
  '3.10.2S',
  '3.10.3S',
  '3.10.4S',
  '3.10.5S',
  '3.10.6S',
  '3.10.2aS',
  '3.10.2tS',
  '3.11.1S',
  '3.11.2S',
  '3.11.0S',
  '3.11.3S',
  '3.11.4S',
  '3.12.0S',
  '3.12.1S',
  '3.12.2S',
  '3.12.3S',
  '3.12.0aS',
  '3.12.4S',
  '3.13.0S',
  '3.13.1S',
  '3.13.2S',
  '3.13.3S',
  '3.13.4S',
  '3.13.2aS',
  '3.13.0aS',
  '3.14.0S',
  '3.14.1S',
  '3.14.2S',
  '3.14.3S',
  '3.14.4S',
  '3.15.0S',
  '3.15.1S',
  '3.15.2S',
  '3.15.1cS',
  '3.15.3S',
  '3.15.4S',
  '3.16.0S',
  '3.16.1S',
  '3.16.0aS',
  '3.16.1aS',
  '3.16.0bS',
  '3.16.0cS',
  '3.17.0S'
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCuw45594'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
