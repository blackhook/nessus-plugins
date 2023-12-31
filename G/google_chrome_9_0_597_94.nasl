#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(51921);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2011-0981",
    "CVE-2011-0982",
    "CVE-2011-0983",
    "CVE-2011-0984",
    "CVE-2011-0985"
  );
  script_bugtraq_id(46262);
  script_xref(name:"SECUNIA", value:"43021");

  script_name(english:"Google Chrome < 9.0.597.94 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 9.0.597.94.  Such versions are reportedly affected by multiple
vulnerabilities :

  - An error exists in the processing of animations events
    related to stale pointers. (Issue #67234)

  - An error exists in the processing of SVG font faces
    which allows attempts to use already freed resources.
    (Issue #68120)

  - An error exists in the processing of anonymous blocks
    related to stale pointers. (Issue #69556)

  - Errors exist in the processing of plugins which allow
    out-of-bounds reads to occur. (Issue #69970)

  - An error exists in the handling of out-of-memory
    conditions and does not always allow processes to be
    properly terminated. (Issue #70456)");
  # https://chromereleases.googleblog.com/2011/02/stable-channel-update_08.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4a1f59e2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome 9.0.597.94 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2022 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");

installs = get_kb_list("SMB/Google_Chrome/*");
google_chrome_check_version(installs:installs, fix:'9.0.597.94', severity:SECURITY_HOLE);
