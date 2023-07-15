#TRUSTED 1828c6e49fd02f34dbd87278506e676d8cec39e3707cd706e5dc92d5825c2629d0a07e1d2e92a3103740ce29c62a25984340734b8ea0d53c58271e507540dcd6edeb2261637dfeabe7aa770755634c02f4055cc53eb7b399c700e4a17c04a577145cc29124bb92515b4e79ec6fb3e9e03bf19a519f7e5abc2f76c6c10ec0221c38aa869b07641dd81c74658b85b701da6f8a9db635b8fa6f67460edfb490dcc8895d37fe9dfa9e42fb98d9ac51c763230e6edca959c46e23fccbd21bfd43e33473d6ac6021bd6f2372dd2e0ddf14be12003e49b7176ff1728ea6f988cc154d69566aff703d7f2f441598b6b5f97f698a3ef323b7ab8552378eaab7b86c47446b35e77b0af95885a8bfce729fa8e004ffd26aef3b82efce1d65bb5d79de593105fb489ec1ae6e7a21cb1d4495cdc5c2b52ad3904cccec518dd579694bd10579093e493ea7c9ba37b42a01cb932ea6e76ca03e22b37f6ea063d12d4b02c6cf369c6fd477ed53e720730d25713d64045cdfdcf7350073b10496d45a62e97f6d7431b467b46323a084a16c12ba6cf02e856016c7631735e9089b674a2e0a8a80bbba5ae12911b5f2d7c225d6ad4b0faef1c33ac9940fabd599581c0caca40bc998a04e26a1248bc91cf273a05ab5c4f57dbb1c47c6d5d3c2534ec008bacdedaba46d45fd1ec541103b4f4577dc307a3e8bb49e272e3b9c0fd2df5e81d60a90320ed4
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(132052);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id(
    "CVE-2018-0182",
    "CVE-2018-0185",
    "CVE-2018-0193",
    "CVE-2018-0194"
  );
  script_bugtraq_id(103547);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuz03145");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuz56419");
  script_xref(name:"CISCO-BUG-ID", value:"CSCva31971");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvb09542");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180328-cmdinj");

  script_name(english:"Cisco IOS XE Software CLI Command Injection Multiple Vulnerabilities (cisco-sa-20180328-cmdinj)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by multiple vulnerabilities in the CLI parser
because the affected software does not sufficiently sanitize command arguments before passing commands to the Linux
shell for execution. An authenticated, local attacker can exploit this, by submitting a malicious CLI command, in order
to gain access to the underlying Linux shell of an affected device and execute commands with root privileges on the
device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-cmdinj
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e07f0cfe");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuz03145");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuz56419");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCva31971");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvb09542");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCuz03145, CSCuz56419, CSCva31971, and CSCvb09542.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0182");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/13");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Settings/ParanoidReport");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');
include('audit.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

vuln_ranges = [{ 'min_ver' : '16.1', 'fix_ver' : '16.3.2' }];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCuz03145, CSCuz56419, CSCva31971, CSCvb09542'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
