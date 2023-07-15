#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(46171);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2010-1663", "CVE-2010-1664", "CVE-2010-1665");
  script_bugtraq_id(39804, 39808, 39813);
  script_xref(name:"SECUNIA", value:"39651");

  script_name(english:"Google Chrome < 4.1.249.1064 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 4.1.249.1064.  Such versions are reportedly affected by multiple
vulnerabilities :

  - A cross-origin bypass in Google URL (GURL). (Issue
    #40445)

  - An HTML5 media handling issue could lead to memory
    corruption. (Issue #40487)

  - A font handling issue could lead to memory corruption.
    (Issue #42294)");
  # https://chromereleases.googleblog.com/2010/04/stable-update-bug-and-security-fixes.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f33868d9");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome 4.1.249.1064 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/28");

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
google_chrome_check_version(installs:installs, fix:'4.1.249.1064', severity:SECURITY_HOLE);
