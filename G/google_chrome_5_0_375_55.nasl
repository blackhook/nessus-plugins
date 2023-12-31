#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(46732);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2010-2105",
    "CVE-2010-2106",
    "CVE-2010-2107",
    "CVE-2010-2108",
    "CVE-2010-2109",
    "CVE-2010-2110"
  );
  script_bugtraq_id(40367);

  script_name(english:"Google Chrome < 5.0.375.55 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 5.0.375.55.  As such, it is reportedly affected by multiple
vulnerabilities :

  - URLs do not closely match the Safe Browsing
    specification. (Issue #7713)

  - It is possible to spoof URLs with unload event handlers.
    (Issue #16535)

  - A memory error exists in the Safe Browsing interaction.
    (Issue #30079)

  - It is possible to bypass the whitelist-mode plugin
    blocker. (Issue #39740)

  - A memory error exists with drag and drop. (Issue #41469)

  - JavaScript is incorrectly executed in the extension
    context. (Issue #42228)");
  # https://chromereleases.googleblog.com/2010/05/stable-channel-update.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5b640e65");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome 5.0.375.55 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/05/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2022 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}


include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");

installs = get_kb_list("SMB/Google_Chrome/*");
google_chrome_check_version(installs:installs, fix:'5.0.375.55', severity:SECURITY_HOLE);
