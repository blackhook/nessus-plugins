#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(59117);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2011-3083",
    "CVE-2011-3084",
    "CVE-2011-3085",
    "CVE-2011-3086",
    "CVE-2011-3087",
    "CVE-2011-3088",
    "CVE-2011-3089",
    "CVE-2011-3090",
    "CVE-2011-3091",
    "CVE-2011-3092",
    "CVE-2011-3093",
    "CVE-2011-3094",
    "CVE-2011-3095",
    "CVE-2011-3097",
    "CVE-2011-3098",
    "CVE-2011-3099",
    "CVE-2011-3100",
    "CVE-2011-3102"
  );
  script_bugtraq_id(53540, 53808);

  script_name(english:"Google Chrome < 19.0.1084.46 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 19.0.1084.46 and is, therefore, affected by the following
vulnerabilities :

  - Video content with FTP can cause crashes.
    (CVE-2011-3083)

  - Internal links are not loaded in their own process.
    (CVE-2011-3084)

  - Lengthy auto-filled values can corrupt the user
    interface. (CVE-2011-3085)

  - Use-after free errors exist related to style elements,
    table handling, indexed DBs, GTK 'omnibox' handling,
    and corrupt font encoding names related to PDF handling.
    (CVE-2011-3086, CVE-2011-3089, CVE-2011-3091,
    CVE-2011-3096, CVE-2011-3099)

  - An error exists related to windows navigation.
    (CVE-2011-3087)

  - Out-of-bounds read errors exist related to hairline
    drawing, glyph handling, Tibetan, OGG containers, PDF
    sampled functions and drawing dash paths.
    (CVE-2011-3088, CVE-2011-3093, CVE-2011-3094,
    CVE-2011-3095, CVE-2011-3097, CVE-2011-3100)

  - A race condition related to workers exists.
    (CVE-2011-3090)

  - An invalid write exists in the v8 regex processing.
    (CVE-2011-3092)

  - An error exists related to Windows Media Player plugin
    and the search path. (CVE-2011-3098)

  - An off-by-one out-of-bounds write error exists in
    libxml. (CVE-2011-3102)");
  # http://googlechromereleases.blogspot.com/2012/05/stable-channel-update.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?57869300");
  # http://build.chromium.org/f/chromium/perf/dashboard/ui/changelog.html?url=/trunk/src&range=119867:129376&mode=html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ac840e6e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome 19.0.1084.46 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2011-3099");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");

installs = get_kb_list("SMB/Google_Chrome/*");
google_chrome_check_version(installs:installs, fix:'19.0.1084.46', severity:SECURITY_HOLE);
