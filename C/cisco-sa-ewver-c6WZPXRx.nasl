#TRUSTED 16468dbefe19361fc83a16b7a37c16616128ec78ad78aed7aa04b0e749eb3af6a8e59be298731239b902d36eec360e2ea0b5f3e22f38122faec1c82c61fe62e889d379a0d86d3a75924e8aa3a48f0629dbae619ac039eb3a100abd18beee9eef5bbcd2da95f92dd16c24ee5882a630c313796a15a5ed9f49325d35f64dcaa01c3c29894a7d3d0cdec62998d74ac649dec04e17152b98adf83acbca72f90a912123c0c17456c32035640a2c24cb48dd6838f7f65b47e6394470f21c5a3717d3f537fc3364e1d568fc33deb4d3170069acb050bdeb23a300eeaf2d54bd58e852e9b327dcf8e8dc3e8e1351528b6ba81bafdf29c8118be76d3167349e3c9f41493fb0fb75e2eed5b31644ebf0cafbfc2e915ab5d5b38376b7628f4e5c6c9edb79919bfe301cdc083049a509bba2cf72b5c386d922b1bd09ed3976ab9e13923e7c6bdd9b49f3b4665b47f3aefacdfa8b3efae83977943b044c4ba5d70f5b62e80cb5a3b430adc7557965e55e1a27ee61da337e9b6a152dd254678d17a25ce8bf722f03cc39c85e19a80fb88bcc02da6d306abb1905d6e6ecf1681c1876945ed2909f7ff570cb970ac5506e5ae61f6548636b07fff9deaa610b0336d1602e45dfe0f5b9bd621e56a811f9afbeda4f8aa39fed8916222521f6728af1bbd84f47650ec48128890c85b6e3065db06597d252cec7411e2390390e9fb1bd2b93fdfd79cc06
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152813);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2021-34715");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy99641");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ewver-c6WZPXRx");
  script_xref(name:"IAVA", value:"2021-A-0389-S");

  script_name(english:"Cisco Expressway Series and TelePresence Video Communication Server Image Verification RCE (cisco-sa-ewver-c6WZPXRx)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Cisco TelePresence Video Communication Server installed on the remote host is affected by a
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco TelePresence Video Communication Server is affected by a vulnerability
in the image verification function that allows an authenticated, remote attacker to execute code with internal user
privileges on the underlying operating system. The vulnerability is due to insufficient validation of the content of
upgrade packages. An attacker could exploit this vulnerability by uploading a malicious archive to the Upgrade page of
the administrative web interface. A successful exploit could allow the attacker to execute code with user-level
privileges (the _nobody account) on the underlying operating system.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ewver-c6WZPXRx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2f58169d");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy99641");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvy99641");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34715");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(347);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_video_communication_server_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_video_communication_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:telepresence_video_communication_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_telepresence_video_communication_server_detect.nbin");
  script_require_keys("Cisco/TelePresence_VCS/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco TelePresence VCS');

var vuln_ranges = [{ 'min_ver':'8.8', 'fix_ver' : '14.0.3' }];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvy99641',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
