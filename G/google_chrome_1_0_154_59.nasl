#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(38154);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2009-1412");
  script_bugtraq_id(34704);

  script_name(english:"Google Chrome < 1.0.154.59 ChromeHTML URI Handling Privilege Escalation");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by a same
origin policy bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 1.0.154.59. Such versions are reportedly affected by an issue
when handling URLs with a 'chromehtml:' protocol that could allow an
attacker to run scripts of his choosing on any page or enumerate files
on the local disk.

If a user has Google Chrome installed, visiting an attacker-controlled
web page in another browser could cause Google Chrome to launch, open
multiple tabs, and load scripts that run after navigating to a URL of
the attacker's choice.");
  # https://chromereleases.googleblog.com/2009/04/stable-update-security-fix.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?82f7094f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome 1.0.154.59 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(200);

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2022 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");

installs = get_kb_list("SMB/Google_Chrome/*");
google_chrome_check_version(installs:installs, fix:'1.0.154.59', severity:SECURITY_WARNING);
