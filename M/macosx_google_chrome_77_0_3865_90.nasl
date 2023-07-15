#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(129053);
  script_version("1.4");
  script_cvs_date("Date: 2019/11/27");

  script_cve_id(
    "CVE-2019-13685",
    "CVE-2019-13686",
    "CVE-2019-13687",
    "CVE-2019-13688"
  );

  script_name(english:"Google Chrome < 77.0.3865.90 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote macOS host is prior to 77.0.3865.90. It is, therefore, affected by
multiple vulnerabilities as referenced in the 2019_09_stable-channel-update-for-desktop_18 advisory. Note that Nessus
has not tested for this issue but has instead relied only on the application's self-reported version number.");
  # https://chromereleases.googleblog.com/2019/09/stable-channel-update-for-desktop_18.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c8cb2aef");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1000934");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/995964");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/998548");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1000002");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 77.0.3865.90 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-13688");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}
include('google_chrome_version.inc');

get_kb_item_or_exit('MacOSX/Google Chrome/Installed');

google_chrome_check_version(fix:'77.0.3865.90', severity:SECURITY_WARNING, xss:FALSE, xsrf:FALSE);
