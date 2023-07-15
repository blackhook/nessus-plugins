#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(56241);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2011-2444");
  script_bugtraq_id(49710);

  script_name(english:"Google Chrome < 14.0.835.186 Multiple Adobe Flash Player Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 14.0.835.186.  Such versions of Chrome contain a vulnerable
version of Adobe Flash Player that is affected by the following
vulnerabilities:

  - An unspecified, critical error for which no further
    details are available at this time.

  - An unspecified cross-site scripting vulnerability.

At least one of these issues are currently being exploited in the
wild.");
  # https://chromereleases.googleblog.com/2011/09/stable-channel-update_20.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?50ce4fcb");
  # http://blogs.adobe.com/psirt/2011/09/prenotification-security-update-for-flash-player.html/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?86ff8535");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome 14.0.835.186 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/09/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2022 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");

installs = get_kb_list("SMB/Google_Chrome/*");
google_chrome_check_version(installs:installs, fix:'14.0.835.186', severity:SECURITY_HOLE);
