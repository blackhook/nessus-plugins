#TRUSTED 1eb7ae53929fd49c35ae9b78cc7db85d3701e1fc3a1c5ea1885e3289386e7228d3adf1177846917069818ce6a742e620aa180c85940724153f459e83d614b1d970d22d8972390f266f8e6f90f7829b4b57f215146a3b2bf8d6f6cda042ba32e7558b0b89a43c61b3c58b5b52beb6ec88bedd0c53dedfee451bc76ced91a4fcca3e21aa875f77b0c32b6a29f9f21d9f3fd09c56899b926918e23075269f8bc45380b653a788f12387803d70d1dd7c7a0a39525fb5d4b4712c94bc083f2736c455d6cdcb594c961c789de08b8501542c1c34f8258e9ad81b50657535b15cf02bde43abe7e52bec24643d81fd2a715be45dab068133091e289d364c05050cff4cb3a27a28f7a428e04f23c912a76f6bc0180944b2f31aa74b205c54ce8a0de0d943b62347ad09d82da78e0d67544d828ea7536ace571799e85194c1f059b77599ef2d5f556ef40638a15f9f7d81ceba440772a20eb7f260d92a6a2100f71cba3c8a94bbbcb0e89f57bb324f75c4bc36c5974cf3148c283997f9ae5128b95544cbd0e68df23862298315616c9c0affbb5ad203ba574c91a303ce5c1af0a095bff1e35d51cba89263d3dfbd67047746ab71dae1a12d964b3f365f510dc7b692909ae539024d9769b8d0e1641b93d46d27f59ee39c8800127486efad47e7c1a0918f2af62df48082d2db85aca514efd037819d9b80b43d4c59994bd58d520ad2dad9bf
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138524);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-3223");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq90852");
  script_xref(name:"CISCO-SA", value:"cisco-sa-webui-filerd-HngnDYGk");
  script_xref(name:"IAVA", value:"2020-A-0239-S");

  script_name(english:"Cisco IOS XE Software Web UI Arbitrary File Read Vulnerability (cisco-sa-webui-filerd-HngnDYGk)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by an arbitrary file read vulnerability.
Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-webui-filerd-HngnDYGk
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bc271b65");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq90852");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvq90852");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3223");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(59);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/16");

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

vuln_versions = make_list(
  '16.9.4',
  '16.9.4c',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.11.1s',
  '16.11.2',
  '16.12.1',
  '16.12.1a',
  '16.12.1c',
  '16.12.1s',
  '16.12.1t',
  '16.12.1w',
  '16.12.1y'
);

workarounds = make_list(CISCO_WORKAROUNDS['HTTP_Server_iosxe']);
workaround_params = {'no_active_sessions' : 1};

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'cmds'     , make_list('show running-config'),
  'bug_id'   , 'CSCvq90852',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:vuln_versions
);
