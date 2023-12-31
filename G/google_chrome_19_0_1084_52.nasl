#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(59255);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2011-3103",
    "CVE-2011-3104",
    "CVE-2011-3105",
    "CVE-2011-3106",
    "CVE-2011-3107",
    "CVE-2011-3108",
    "CVE-2011-3110",
    "CVE-2011-3111",
    "CVE-2011-3112",
    "CVE-2011-3113",
    "CVE-2011-3114",
    "CVE-2011-3115"
  );
  script_bugtraq_id(53679);

  script_name(english:"Google Chrome < 19.0.1084.52 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 19.0.1084.52 and is, therefore, affected by the following
vulnerabilities :

  - An error exists in the v8 JavaScript engine that can
    cause application crashes during garbage collection.
    (CVE-2011-3103)

  - An out-of-bounds read error exists related to 'Skia'.
    (CVE-2011-3104)

  - Use-after-free errors exist related to
    'first-letter handling', browser cache, and invalid
    encrypted PDFs. (CVE-2011-3105, CVE-2011-3108,
    CVE-2011-3112)

  - A memory corruption error exists related to websockets
    and SSL. (CVE-2011-3106)

  - An error exists related to plugin-in JavaScript
    bindings that can cause the application to crash.
    (CVE-2011-3107)

  - An out-of-bounds write error exists related to PDF
    processing. (CVE-2011-3110)

  - An invalid read error exists related to the v8
    JavaScript engine. (CVE-2011-3111)

  - An invalid cast error exists related to colorspace
    handling in PDF processing. (CVE-2011-3113)

  - A buffer overflow error exists related to PDF
    functions. (CVE-2011-3114)

  - A type corruption error exists related to the v8
    JavaScript engine. (CVE-2011-3115)");
  # https://chromereleases.googleblog.com/2012/05/stable-channel-update_23.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cb4464c8");
  # http://build.chromium.org/f/chromium/perf/dashboard/ui/changelog.html?url=/branches/1084/src&range=135956:138391&mode=html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e39931c9");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome 19.0.1084.52 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2011-3108");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/24");

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
google_chrome_check_version(installs:installs, fix:'19.0.1084.52', severity:SECURITY_HOLE);
