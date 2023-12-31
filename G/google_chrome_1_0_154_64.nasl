#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(38699);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2009-1441", "CVE-2009-1442");
  script_bugtraq_id(34859);
  script_xref(name:"SECUNIA", value:"35014");

  script_name(english:"Google Chrome < 1.0.154.64 Multiple Overflows");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 1.0.154.64. Such versions are reportedly affected by multiple
vulnerabilities :

  - A failure to properly validate input from a renderer
    (tab) process could allow an attacker to crash the
    browser and possibly run arbitrary code with the
    privileges of the logged on user. (CVE-2009-1441)

  - A failure to check the result of integer multiplication
    when computing image sizes could allow a specially
    crafted image or canvas to cause a tab to crash and
    possibly allow an attacker to execute arbitrary code
    inside the (sandboxed) renderer process. (CVE-2009-1442)");
  # https://chromereleases.googleblog.com/2009/05/stable-update-security-fix.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5479ada5");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome 1.0.154.64 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/07");

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
google_chrome_check_version(installs:installs, fix:'1.0.154.64', severity:SECURITY_HOLE);
