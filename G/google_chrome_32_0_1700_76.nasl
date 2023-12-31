#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(71968);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2013-6641",
    "CVE-2013-6643",
    "CVE-2013-6644",
    "CVE-2013-6645",
    "CVE-2013-6646"
  );
  script_bugtraq_id(64805, 64981, 65066);

  script_name(english:"Google Chrome < 32.0.1700.76 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is a version
prior to 32.0.1700.76.  It is, therefore, affected by the following
vulnerabilities :

  - Use-after-free errors exist related to forms, web
    workers and speech input elements. (CVE-2013-6641,
    CVE-2013-6645, CVE-2013-6646)

  - An unspecified error exists related to Google accounts
    and the sync process. (CVE-2013-6643)

  - Various unspecified errors exist having unspecified
    impacts. (CVE-2013-6644)

  - An input validation error exists related to the
    included WebKit component 'XSS Auditor' and the
    handling of the 'srcdoc' attribute that could allow
    cross-site scripting attacks.");
  # http://googlechromereleases.blogspot.com/2014/01/stable-channel-update.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?13bff2a9");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome 32.0.1700.76 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-6646");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");
installs = get_kb_list("SMB/Google_Chrome/*");

google_chrome_check_version(installs:installs, fix:'32.0.1700.76', severity:SECURITY_HOLE, xss:TRUE);
