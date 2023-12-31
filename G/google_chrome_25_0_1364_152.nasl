#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(65029);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2013-0902",
    "CVE-2013-0903",
    "CVE-2013-0904",
    "CVE-2013-0905",
    "CVE-2013-0906",
    "CVE-2013-0907",
    "CVE-2013-0908",
    "CVE-2013-0909",
    "CVE-2013-0910",
    "CVE-2013-0911"
  );
  script_bugtraq_id(
    59515,
    59516,
    59517,
    59518,
    59519,
    59520,
    59521,
    59522,
    59523,
    59524
  );

  script_name(english:"Google Chrome < 25.0.1364.152 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is a
version prior to 25.0.1364.152. It is, therefore, affected by the
following vulnerabilities :

  - Use-after-free errors exist related to the frame
    loader, browser navigation handling and SVG
    animation. (CVE-2013-0902, CVE-2013-0903, CVE-2013-0905)

  - Memory corruption errors exist related to 'Web Audio'
    and 'Indexed DB'. (CVE-2013-0904, CVE-2013-0906)

  - A race condition exists related to media thread
    handling. (CVE-2013-0907)

  - An unspecified error exists related to extension
    process bindings. (CVE-2013-0908)

  - The 'XSS Auditor' could leak referrer information.
    (CVE-2013-0909)

  - An unspecified error exists related to loading
    strictness and 'Mediate renderer -> browser plug-in'.
    (CVE-2013-0910)

  - A path traversal error exists related to database
    handling. (CVE-2013-0911)");
  # https://chromereleases.googleblog.com/2013/03/stable-channel-update_4.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f8ae6261");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome 25.0.1364.152 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-0911");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");

installs = get_kb_list("SMB/Google_Chrome/*");
google_chrome_check_version(installs:installs, fix:'25.0.1364.152', severity:SECURITY_HOLE);
