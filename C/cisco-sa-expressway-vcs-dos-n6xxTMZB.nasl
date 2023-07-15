#TRUSTED 733775aefdc0c8e905a753b94687dadea42c8196af7381c7d5ac2e60c255bd96d971717325dae25759849be43ad7dfece58fb5c90220f03c5921338cf83b029723533339a08d55393b6898f4aaaea899019c0d65197bafa0532f9d2391d7f378920bbc9297c5b7f46bdfb5e48a896c3495bdeddddbc9cbd26dd83620df37baff410b52f57b7a4f2d563e9b39159ec7d4daf0c2cd53c0aad23a33bf6cc2282bfaa53192910540172a8f81e07cbb32db1f4e65eac5fa941b8776772428f72e75f34d5cbfe1a6ecb5eb274d021c01f9308414908ef6cb62e32afa687231252a93e3bc8ef17c9a46e3a3f7d8b0b533a258480932760ea4c1fcc84879f38d546f28a79f203fd654ce402c282e6246d48114c45552d5204358e66e9b2390474a30aa498012d70a384664002fe491fc41f11b8c6acca62fc8720df804d4cfc7143a4e91fa4b7019b64a4c0658a25cf98638a675db8784cec4bb43aaf38b5e6569cf570d2cfb56451a2ba588c1fb223723954596c8e8d2e2264a6e369960da412459d49406bed3d8ab677b0c601f9a8e398f95d7278a57cfc849f48a141dd52e68bb74100adefd6cc8ed00ea6457e426906a39f97a45805f92dd7acbd501e22fd6abb14153b865efbf422cd79c92d18be939ac9c172c0212020bd31115a4fa7c3392ccc500c31e984425be5c951373cc543497c9306fd189416a89dc22045717b3279067
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(141361);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2020-3596");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu78519");
  script_xref(name:"CISCO-SA", value:"cisco-sa-expressway-vcs-dos-n6xxTMZB");
  script_xref(name:"IAVA", value:"2020-A-0449-S");

  script_name(english:"Cisco Expressway Series and TelePresence Video Communication DoS (cisco-sa-expressway-vcs-dos-n6xxTMZB)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Cisco TelePresence Video Communication Server installed on the remote host is affected by a DoS vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of Cisco TelePresence Video Communication Server is affected
by a denial of service (DoS) vulnerability in the Session Initiation Protocol (SIP) due to incorrect handling of
incoming SIP packets to an affected device. An unauthenticated, remote attacker can exploit this, by sending a series
of SIP packets to an affected device, in order to cause a DoS condition.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu78519");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-expressway-vcs-dos-n6xxTMZB
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e1af5099");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu78519.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3596");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_video_communication_server_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_video_communication_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:telepresence_video_communication_server");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_telepresence_video_communication_server_detect.nbin");
  script_require_keys("Cisco/TelePresence_VCS/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco TelePresence VCS');

vuln_ranges = [{ 'min_ver':'0', 'fix_ver' : '12.6.4' }];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvu78519',
  'disable_caveat' , TRUE,
  'fix'      , 'See vendor advisory'
);

cisco::check_and_report(product_info:product_info, reporting:reporting, vuln_ranges:vuln_ranges);
