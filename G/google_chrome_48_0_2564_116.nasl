#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(88956);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2016-1629");

  script_name(english:"Google Chrome < 48.0.2564.116 Blink Same-Origin Policy Bypass");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
a security bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is
prior to 48.0.2564.116. It is, therefore, affected by an unspecified
flaw related to the Blink rendering engine. An attacker can exploit
this to bypass same-origin policy restrictions and escape the sandbox,
allowing the attacker to execute arbitrary code with elevated
privileges.");
  # http://googlechromereleases.blogspot.com/2016/02/stable-channel-update_18.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?63641ede");
  script_set_attribute(attribute:"see_also", value:"http://www.chromium.org/blink");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 48.0.2564.116 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-1629");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");
installs = get_kb_list("SMB/Google_Chrome/*");

google_chrome_check_version(installs:installs, fix:'48.0.2564.116', severity:SECURITY_HOLE);
