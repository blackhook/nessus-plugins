#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(87417);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2015-6792");

  script_name(english:"Google Chrome < 47.0.2526.106 Multiple RCE");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is
prior to 47.0.2526.106. It is, therefore, affected by multiple
vulnerabilities :

  - The WebCursor::Deserialize() method in file
    common/cursors/webcursor.cc. is affected by an integer
    overflow condition that allows an attacker to execute
    arbitrary code.

  - The MidiManagerAlsa::DispatchSendMidiData() method in
    file media/midi/midi_manager_alsa.cc contains a
    unspecified flaw that allows an attacker to execute
    arbitrary code outside of sandbox restrictions.");
  # http://googlechromereleases.blogspot.com/2015/12/stable-channel-update_15.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b00a2b47");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 47.0.2526.106 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-6792");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");
installs = get_kb_list("SMB/Google_Chrome/*");

google_chrome_check_version(installs:installs, fix:'47.0.2526.106', severity:SECURITY_HOLE);
