#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(49237);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2010-1823",
    "CVE-2010-1824",
    "CVE-2010-1825",
    "CVE-2010-3412",
    "CVE-2010-3413",
    "CVE-2010-3415",
    "CVE-2010-3417"
  );
  script_bugtraq_id(43228, 46677);
  script_xref(name:"MSVR", value:"MSVR11-001");

  script_name(english:"Google Chrome < 6.0.472.59 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 6.0.472.59.  Such versions are reportedly affected by multiple
vulnerabilities :

  - A use-after-free error exists when using document APIs
    during parse. (Issue #50250)

  - A use-after-free error exists in SVG styles.
   (Issue #50712)

  - A use-after-free error exists with nested SVG elements.
   (Issue #51252)

  - A race condition exists in console handling.
    (Issue #51919)

  - An unlikely browser crash exists in pop-up blocking.
    (Issue #53176)

  - A memory corruption error exists in Geolocation.
    (Issue #53394)

  - An error exists by failing to prompt for extension
    history access. (Issue #54006)");
  # https://chromereleases.googleblog.com/2010/09/stable-beta-channel-updates_14.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?03c00fdf");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome 6.0.472.59 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/15");

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
google_chrome_check_version(installs:installs, fix:'6.0.472.59', severity:SECURITY_HOLE);
