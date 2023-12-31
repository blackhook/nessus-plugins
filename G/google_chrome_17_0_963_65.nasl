#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(58206);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2011-3031",
    "CVE-2011-3032",
    "CVE-2011-3033",
    "CVE-2011-3034",
    "CVE-2011-3035",
    "CVE-2011-3036",
    "CVE-2011-3037",
    "CVE-2011-3038",
    "CVE-2011-3039",
    "CVE-2011-3040",
    "CVE-2011-3041",
    "CVE-2011-3042",
    "CVE-2011-3043",
    "CVE-2011-3044"
  );
  script_bugtraq_id(52271);

  script_name(english:"Google Chrome < 17.0.963.65 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 17.0.963.65 and is, therefore, affected by the following
vulnerabilities:

  - Use-after-free errors exist related to 'v8 element
    wrapper', SVG value handling, SVG document handling,
    SVG use handling, multi-column handling, quote
    handling, class attribute handling, table section
    handling, flexbox with floats and SVG animation
    elements. (CVE-2011-3031, CVE-2011-3032, CVE-2011-3034,
    CVE-2011-3035, CVE-2011-3038, CVE-2011-3039,
    CVE-2011-3041, CVE-2011-3042, CVE-2011-3043,
    CVE-2011-3044)

  - An error exists in the 'Skia' drawing library that can
    allow buffer overflows. (CVE-2011-3033)

  - Casting errors exist related to line box handling and
    anonymous block splitting. (CVE-2011-3036,
    CVE-2011-3037)

  - An out-of-bounds read error exists related to text
    handling. (CVE-2011-3040)");
  # https://chromereleases.googleblog.com/2012/03/chrome-stable-update.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eaef2f21");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome 17.0.963.65 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/05");

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
google_chrome_check_version(installs:installs, fix:'17.0.963.65', severity:SECURITY_HOLE);
