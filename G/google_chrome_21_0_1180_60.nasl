#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(61381);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2012-2847",
    "CVE-2012-2848",
    "CVE-2012-2849",
    "CVE-2012-2850",
    "CVE-2012-2851",
    "CVE-2012-2852",
    "CVE-2012-2853",
    "CVE-2012-2854",
    "CVE-2012-2855",
    "CVE-2012-2856",
    "CVE-2012-2857",
    "CVE-2012-2858",
    "CVE-2012-2860"
  );
  script_bugtraq_id(54749);

  script_name(english:"Google Chrome < 21.0.1180.60 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 21.0.1180.60 and is, therefore, affected by the following
vulnerabilities :

  - Re-prompts are not displayed for excessive
    downloads. (CVE-2012-2847)

  - Drag and drop file access restrictions are not
    restrictive enough. (CVE-2012-2848)

  - An off-by-one read error exists related to GIF
    decoding. (CVE-2012-2849)

  - Various, unspecified errors exist related to PDF
    processing. (CVE-2012-2850)

  - Various, unspecified integer overflows exist related
    to PDF processing. (CVE-2012-2851)

  - A use-after-free error exists related to object linkage
    and PDF processing. (CVE-2012-2852)

  - An error exists related to 'webRequest' and 'Chrome Web
    Store' interference. (CVE-2012-2853)

  - Pointer values can be leaked to 'WebUI' renderers.
    (CVE-2012-2854)

  - An unspecified use-after-free error exists related to
    PDF processing. (CVE-2012-2855)

  - Unspecified out-of-bounds reads exist related to the
    PDF viewer. (CVE-2012-2856)

  - A use-after-free error exists related to CSS DOM
    processing. (CVE-2012-2857)

  - A buffer overflow exists related to 'WebP' decoding.
    (CVE-2012-2858)

  - An out-of-bounds access error exists related to the
    date picker. (CVE-2012-2860)");
  # https://chromereleases.googleblog.com/2012/07/stable-channel-release.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f12f62f1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome 21.0.1180.60 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-2856");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");

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
google_chrome_check_version(installs:installs, fix:'21.0.1180.60', severity:SECURITY_HOLE);
