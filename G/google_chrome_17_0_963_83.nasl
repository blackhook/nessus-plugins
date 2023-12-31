#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(58434);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2011-3045",
    "CVE-2011-3049",
    "CVE-2011-3050",
    "CVE-2011-3051",
    "CVE-2011-3052",
    "CVE-2011-3053",
    "CVE-2011-3054",
    "CVE-2011-3055",
    "CVE-2011-3056",
    "CVE-2011-3057"
  );
  script_bugtraq_id(52453, 52674, 53407);

  script_name(english:"Google Chrome < 17.0.963.83 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 17.0.963.83 and is, therefore, affected by the following
vulnerabilities :

  - An unspecified integer issue exists in libpng.
    (CVE-2011-3045)

  - An error exists related to the extension web request
    API that could allow denial of service attacks.
    Note this issue was corrected in a previous, unspecified
    release. (CVE-2011-3049)

  - Use-after-free errors exist related to 'first-letter'
    handling, CSS cross-fade handling and block splitting.
    (CVE-2011-3050, CVE-2011-3051, CVE-2011-3053)

  - A memory corruption error exists related to WebGL
    canvas handling. (CVE-2011-3052)

  - An error exists related to webui privilege isolation.
    (CVE-2011-3054)

  - Installation of unpacked extensions does not use the
    application's native user interface for prompts.
    (CVE-2011-3055)

  - A cross-origin violation is possible with 'magic iframe'.
    (CVE-2011-3056)

  - The v8 JavaScript engine could allow invalid reads to
    take place. (CVE-2011-3057)");
  # https://chromereleases.googleblog.com/2012/03/stable-channel-update_21.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?01de83e1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome 17.0.963.83 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2022 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");

installs = get_kb_list("SMB/Google_Chrome/*");
google_chrome_check_version(installs:installs, fix:'17.0.963.83', severity:SECURITY_HOLE);
