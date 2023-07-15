#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(70494);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2013-2925",
    "CVE-2013-2926",
    "CVE-2013-2927",
    "CVE-2013-2928"
  );
  script_bugtraq_id(
    63024,
    63025,
    63026,
    63028
  );

  script_name(english:"Google Chrome < 30.0.1599.101 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is a version
prior to 30.0.1599.101. It is, therefore, affected by multiple
vulnerabilities :

  - Use-after-free errors exist related to editing, forms,
    and XmlHttpRequest (XHR). (CVE-2013-2925, CVE-2013-2926,
    CVE-2013-2927)

  - Various, unspecified errors exist. (CVE-2013-2928)");
  # http://googlechromereleases.blogspot.com/2013/10/stable-channel-update_15.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b19cce80");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome 30.0.1599.101 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-2928");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");

installs = get_kb_list("SMB/Google_Chrome/*");
google_chrome_check_version(installs:installs, fix:'30.0.1599.101', severity:SECURITY_HOLE);
