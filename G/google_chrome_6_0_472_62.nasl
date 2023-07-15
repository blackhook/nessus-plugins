#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(49285);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2010-1822", "CVE-2010-3729", "CVE-2010-3730");
  script_bugtraq_id(43205, 43315, 44647);

  script_name(english:"Google Chrome < 6.0.472.62 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 6.0.472.62.  Such versions are reportedly affected by multiple
vulnerabilities :

  - There is a bad cast with malformed SVGs. (Issue #55114)

  - The buffer is mismanaged in the SPDY protocol.
    (Issue #55119)

  - A cross-origin property pollution issue exists.
    (Issue #55350)");
  # https://chromereleases.googleblog.com/2010/09/stable-beta-channel-updates_17.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1a8fbf8b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome 6.0.472.62 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/20");

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
google_chrome_check_version(installs:installs, fix:'6.0.472.62', severity:SECURITY_HOLE);
