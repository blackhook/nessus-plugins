#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(67232);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2013-2853",
    "CVE-2013-2867",
    "CVE-2013-2868",
    "CVE-2013-2869",
    "CVE-2013-2870",
    "CVE-2013-2871",
    "CVE-2013-2872",
    "CVE-2013-2873",
    "CVE-2013-2874",
    "CVE-2013-2875",
    "CVE-2013-2876",
    "CVE-2013-2877",
    "CVE-2013-2878",
    "CVE-2013-2879",
    "CVE-2013-2880"
  );
  script_bugtraq_id(
    61046,
    61047,
    61049,
    61050,
    61051,
    61052,
    61053,
    61054,
    61055,
    61056,
    61057,
    61058,
    61059,
    61060,
    61061
  );

  script_name(english:"Google Chrome < 28.0.1500.71 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is a version
prior to 28.0.1500.71 and is, therefore, affected by multiple
vulnerabilities :

  - A vulnerability exists that exposes HTTP in SSL to a
    man-in-the-middle attack. (CVE-2013-2853)

  - Block pop-unders in various scenarios. (CVE-2013-2867)

  - An error exists related to an incorrect sync of the
    NPAPI extension component. (CVE-2013-2868)

  - An unspecified flaw exists due to a lack of entropy in
    renderers. (CVE-2013-2872)

  - Use-after-free errors exist related to network sockets,
    input handling, and resource loading. (CVE-2013-2870,
    CVE-2013-2871, CVE-2013-2873)

  - A screen data leak error exists related to GL textures.
    (CVE-2013-2874)

  - An extension permission error exists related to
    interstitials.  (CVE-2013-2876)

  - Multiple out-of-bounds errors exist related to JPEG2000,
    SVG, text handling and XML parsing.  (CVE-2013-2869,
    CVE-2013-2875, CVE-2013-2877, CVE-2013-2878)

  - An unspecified error exists when setting up sign-in and
    sync. (CVE-2013-2879)

  - The vendor reports various, unspecified errors exist.
    (CVE-2013-2880)");
  # https://chromereleases.googleblog.com/2013/07/stable-channel-update.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f68d8c39");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome 28.0.1500.71 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-2870");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/10");

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
google_chrome_check_version(installs:installs, fix:'28.0.1500.71', severity:SECURITY_HOLE);
