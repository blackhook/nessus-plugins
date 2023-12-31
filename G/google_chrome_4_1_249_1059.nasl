#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(45610);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2010-1500",
    "CVE-2010-1502",
    "CVE-2010-1503",
    "CVE-2010-1504",
    "CVE-2010-1505",
    "CVE-2010-1506",
    "CVE-2010-1767"
  );
  script_bugtraq_id(
    39667,
    39669,
    39806,
    39807,
    39809,
    39812,
    39814
  );
  script_xref(name:"SECUNIA", value:"39544");

  script_name(english:"Google Chrome < 4.1.249.1059 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 4.1.249.1059.  Such versions are reportedly affected by multiple
vulnerabilities :

  - An error related to type confusion with forms.
    (Issue #39443)

  - An HTTP request error leading to a possible cross-site
    request forgery. (Issue #39698)

  - A local file reference through developer tools.
    (Issue #40136)

  - A cross-site scripting issue in chrome://net-internals.
    (Issue #40137)

  - A cross-site scripting issue in chrome://downloads.
    (Issue #40138)

  - Pages might load with the privileges of the new tab
    page. (Issue #40575)

  - A memory corruption vulnerability in V8 bindings.
    (Issue #40635)");
  # https://chromereleases.googleblog.com/2010/04/stable-update-security-fixes.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1c8d38da");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome 4.1.249.1059 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/23");

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
google_chrome_check_version(installs:installs, fix:'4.1.249.1059', xss:TRUE, severity:SECURITY_HOLE);
