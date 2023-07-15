#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(59958);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2012-2842", "CVE-2012-2843", "CVE-2012-2844");
  script_bugtraq_id(54386);

  script_name(english:"Google Chrome < 20.0.1132.57 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 20.0.1132.57 and is, therefore, affected by the following
vulnerabilities :

  - Use-after-free errors exist related to counter handling
    and layout height tracking. (CVE-2012-2842,
    CVE-2012-2843)

  - An error exists related to JavaScript object accesses
    in PDF handling. (CVE-2012-2844)");
  # https://chromereleases.googleblog.com/2012/07/stable-channel-update.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8ee81c4c");
  # http://build.chromium.org/f/chromium/perf/dashboard/ui/changelog.html?url=/branches/1132/src&range=145807:144678&mode=html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?19ceb022");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome 20.0.1132.57 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/12");

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
google_chrome_check_version(installs:installs, fix:'20.0.1132.57', severity:SECURITY_HOLE);
