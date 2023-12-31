#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(45086);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2010-1229",
    "CVE-2010-1230",
    "CVE-2010-1231",
    "CVE-2010-1232",
    "CVE-2010-1233",
    "CVE-2010-1234",
    "CVE-2010-1235",
    "CVE-2010-1236",
    "CVE-2010-1237"
  );
  script_bugtraq_id(38829, 73629, 73673);
  script_xref(name:"SECUNIA", value:"39029");

  script_name(english:"Google Chrome < 4.1.249.1036 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is prior to
4.1.249.1036. It is, therefore, affected by multiple vulnerabilities :

  - Multiple race conditions and pointer errors in the
    sandbox infrastructure. (Issue #28804, #31880)

  - An error relating to persisted metadata such as Web
    Databases and STS. (Issue #20801, #33445)

  - HTTP headers are processed before the SafeBrowsing
    check. (Issue #33572)

  - A memory error with malformed SVG. (Issue #34978)

  - Multiple integer overflows in WebKit JavaScript objects.
    (Issue #35724)

  - The HTTP basic auth dialog truncates URLs.
    (Issue #36772)

  - It is possible to bypass the download warning dialog.
    (Issue #37007)

  - An unspecified cross-origin bypass vulnerability.
    (Issue #37383)

  - A memory error relating to empty SVG elements. Note
    that this only affects Chrome Beta versions.
    (Issue #37061)");
  # https://chromereleases.googleblog.com/2010/03/stable-channel-update.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0ec0e092");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome 4.1.249.1036 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/18");

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
google_chrome_check_version(installs:installs, fix:'4.1.249.1036', severity:SECURITY_HOLE);
