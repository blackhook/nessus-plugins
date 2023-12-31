#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(72800);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2013-6663",
    "CVE-2013-6664",
    "CVE-2013-6665",
    "CVE-2013-6666",
    "CVE-2013-6667",
    "CVE-2013-6668"
  );
  script_bugtraq_id(65930);

  script_name(english:"Google Chrome < 33.0.1750.146 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is a
version prior to 33.0.1750.146.  It is, therefore, affected by the
following vulnerabilities :

  - Use-after-free errors exist related to handling
    SVG images and speech recognition processing.
    (CVE-2013-6663, CVE-2013-6664)

  - An error exists related to software rendering that
    could allow heap-based buffer overflows.
    (CVE-2013-6665)

  - An error exists related to Flash header requests.
    (CVE-2013-6666)

  - Various unspecified errors exist having unspecified
    impacts. (CVE-2013-6667)

  - Unspecified errors exist related to the V8 JavaScript
    engine that could have unspecified impacts.
    (CVE-2013-6668)");
  # http://googlechromereleases.blogspot.com/2014/03/stable-channel-update.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?246aa148");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome 33.0.1750.146 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-6668");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/04");

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

google_chrome_check_version(installs:installs, fix:'33.0.1750.146', severity:SECURITY_HOLE);
