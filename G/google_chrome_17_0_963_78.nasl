#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(58328);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2011-3046");
  script_bugtraq_id(52357, 52369);

  script_name(english:"Google Chrome < 17.0.963.78 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 17.0.963.78 and is, therefore, affected by the following
vulnerabilities:

  - The application does not properly handle history
    navigation.

  - An unspecified universal cross-site scripting issue
    exists.

By exploiting these vulnerabilities in combination, an attacker could
bypass Chrome's sandbox and execute arbitrary code on the target
machine as demonstrated in March 2012 at Google's Pwnium
competition.");
  # https://chromereleases.googleblog.com/2012/03/chrome-stable-channel-update.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?60a53d99");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome 17.0.963.78 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2022 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");

installs = get_kb_list("SMB/Google_Chrome/*");
google_chrome_check_version(installs:installs, fix:'17.0.963.78', severity:SECURITY_HOLE, xss:TRUE);
