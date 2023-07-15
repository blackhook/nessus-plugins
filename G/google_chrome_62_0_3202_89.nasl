#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104434);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2017-15398", "CVE-2017-15399");

  script_name(english:"Google Chrome < 62.0.3202.89 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is
prior to 62.0.3202.89. It is, therefore, affected by multiple 
vulnerabilities as noted in Chrome stable channel update release notes.
Please refer to the release notes for additional information.

Note that Nessus has not attempted to exploit these issues but has
instead relied only on the application's self-reported version number.");
  # https://chromereleases.googleblog.com/2017/11/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4af6a216");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 62.0.3202.89 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2022 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");
installs = get_kb_list("SMB/Google_Chrome/*");

google_chrome_check_version(installs:installs, fix:'62.0.3202.89', severity:SECURITY_HOLE);
