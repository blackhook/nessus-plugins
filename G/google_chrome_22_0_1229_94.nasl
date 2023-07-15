#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(62519);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2012-5112");
  script_bugtraq_id(55867);

  script_name(english:"Google Chrome < 22.0.1229.94 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 22.0.1229.94 and is, therefore, affected by the following
vulnerabilities :

  - A use-after-free error exists related to SVG handling
    that can be used to exploit the renderer process.
    (Issue #154983)

  - An unspecified error exists related to IPC handling
    that can allow an attacker to escape the application
    sandbox. (Issue #154987)

Successful exploitation of any of these issues could lead to an
application crash or even allow arbitrary code execution, subject to the
user's privileges.");
  # https://chromereleases.googleblog.com/2012/10/stable-channel-update_6105.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?51b71ff9");
  # https://blog.chromium.org/2012/10/pwnium-2-results-and-wrap-up_10.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2b40fd03");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome 22.0.1229.94 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-5112");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");

installs = get_kb_list("SMB/Google_Chrome/*");
google_chrome_check_version(installs:installs, fix:'22.0.1229.94', severity:SECURITY_HOLE);
