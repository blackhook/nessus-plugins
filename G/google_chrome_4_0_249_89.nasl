#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(44587);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2010-0315",
    "CVE-2010-0556",
    "CVE-2010-0643",
    "CVE-2010-0644",
    "CVE-2010-0645",
    "CVE-2010-0646",
    "CVE-2010-0647",
    "CVE-2010-0649"
  );
  script_bugtraq_id(38177);
  script_xref(name:"SECUNIA", value:"38545");

  script_name(english:"Google Chrome < 4.0.249.89 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 4.0.249.89.  Such versions are reportedly affected by multiple
vulnerabilities :

  - Two errors when resolving domain names and when
    interpreting configured proxy lists can be exploited to
    disclose sensitive data. (Issue #12303, #22914)

  - Multiple integer overflows in the V8 engine.
    (Issue #31009)

  - An unspecified error when processing the '<ruby>' tag.
    (Issue #31692)

  - Chrome leaks redirection targets via the '<iframe>'
    href. (Issue #32309)

  - An unspecified error when displaying domain names in
    HTTP authentication dialogs. (Issue #37218)

  - An integer overflow when deserializing sandbox messages.
    (Issue #32915)");
  # https://chromereleases.googleblog.com/2010/02/stable-channel-update.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?926a743d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome 4.0.249.89 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(94, 189, 200, 255);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/11");

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
google_chrome_check_version(installs:installs, fix:'4.0.249.89', severity:SECURITY_HOLE);
