#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(51872);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2011-0777",
    "CVE-2011-0778",
    "CVE-2011-0779",
    "CVE-2011-0780",
    "CVE-2011-0781",
    "CVE-2011-0783",
    "CVE-2011-0784"
  );
  script_bugtraq_id(46144);
  script_xref(name:"SECUNIA", value:"43193");

  script_name(english:"Google Chrome < 9.0.597.84 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 9.0.597.84.  It therefore is reportedly affected by multiple
vulnerabilities :

  - A use-after-free issue exists in image loading.
    (Issue #55381)

  - An unspecified issue exists relating to cross-origin
    drag and drop. (Issue #59081)

  - A browser crash can occur when handling extensions with
    a missing key. (Issue #62791)

  - A browser crash issue exists relating to the PDF event
    handler. (Issue #64051)

  - An unspecified issue exists relating to the merging of
    autofill profiles. (Issue #65669)

  - A browser crash issue exists relating to bad volume
    settings. (Issue #68244)

  - A race condition exists in audio handling.
    (Issue #69195)");
  # https://chromereleases.googleblog.com/2011/02/stable-channel-update.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?717c5939");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome 9.0.597.84 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/04");

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
google_chrome_check_version(installs:installs, fix:'9.0.597.84', severity:SECURITY_HOLE);
