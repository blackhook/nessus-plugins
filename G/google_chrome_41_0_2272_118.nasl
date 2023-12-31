#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(82534);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2015-1233", "CVE-2015-1234");
  script_bugtraq_id(73484, 73486);

  script_name(english:"Google Chrome < 41.0.2272.118 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is
prior to 41.0.2272.118. It is, therefore, affected by the following
vulnerabilities :

  - A remote code execution vulnerability exists due to bugs
    in the V8, Gamepad, and IPC components. (CVE-2015-1233)

  - A buffer overflow vulnerability exists due to a race
    condition in the GPU component. (CVE-2015-1234)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # http://googlechromereleases.blogspot.com/2015/04/stable-channel-update.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6c579b1f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome 41.0.2272.118 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-1233");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/02");

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

google_chrome_check_version(installs:installs, fix:'41.0.2272.118', severity:SECURITY_HOLE);
