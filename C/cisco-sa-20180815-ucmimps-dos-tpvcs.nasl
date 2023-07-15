#TRUSTED 567d8b119b59908ba9615a8bb17d5bd8e9c93faa6369ccb5d16346ba1d3fb9516904a6dc4c142350b3e246830fdd28a53d1cd5d8692ee70d4e45dd0d470dcb42f7d1fd32c76e25090c0f4079253cca03e949320913541411bfb4a5e5cb6a4fb315c6b9bafdacf907ce2628edfab3ee1663856e470690b761a3300244c21fc84eb8136952799a695795620957bff329bb19c19de682831764abbd2eced9df98e6f2ff8df5c4a59dc22d643b6703b9725753f12ef9aabc24fcad8179907661007e77e50f1dbcfcc67830a193786b5115e9060d8d8a88b8b83560e763ecaeccf87e1dd1e1ddcc5db4435a5399fb298fb55d20e3eef8d73a07d0787b27f154a950ed89cfde2cb45bf143eb41ce7dafcbc74dd3b4bff363f5f7fc6210afce87a3c597e104144d18ecb85e24673443940a77ca764c0c184ab372838647b9ba187536b8f753557c1723c83a3c067ca04e468fb4f51413732752116d14db802c57ddfecfeb607001f0c32fd3cd19a8aae9fc358b7cab1d2d44bd1bc77a655fcde193f6d94b322dcd1f917d4c1563870482ccf0e3aff824911d7a1b836376b641b2cb2e68d0348f8163cc67f294483ae12faa7eed373e863c207164fc09f45926ffab86d53604eb2b59b9554eecc45af03a7ad1d6dc4d6f58658934faccb661871c4db865a0d1989a1e65b972d2c6f87e0b1c89fe0ccf552abc46e02378a823d0a2d7f685
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(112218);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2018-0409");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi55947");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180815-ucmimps-dos");

  script_name(english:"Cisco TelePresence VCS / Expressway < 8.11 DoS");

  script_set_attribute(attribute:"synopsis", value:
"A video conferencing application running on the remote host is
affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco TelePresence Video
Communication Server (VCS) / Expressway running on the remote host is
prior to 8.11.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180815-ucmimps-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fb165fe3");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi55947");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco TelePresence VCS / Expressway version 8.11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0409");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/31");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:telepresence_video_communication_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_video_communication_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_video_communication_server_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:expressway_software");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_telepresence_video_communication_server_detect.nbin");
  script_require_keys("Cisco/TelePresence_VCS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco TelePresence VCS");

vuln_ranges = [{ 'min_ver' : '0', 'fix_ver' : '8.11' }];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , "CSCvi55947");

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_ranges:vuln_ranges);
