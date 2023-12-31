#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84051);
  script_version("1.15");
  script_cvs_date("Date: 2019/11/22");

  script_cve_id(
    "CVE-2015-3096",
    "CVE-2015-3098",
    "CVE-2015-3099",
    "CVE-2015-3100",
    "CVE-2015-3102",
    "CVE-2015-3103",
    "CVE-2015-3104",
    "CVE-2015-3105",
    "CVE-2015-3106",
    "CVE-2015-3107",
    "CVE-2015-3108"
  );
  script_bugtraq_id(
    75080,
    75081,
    75084,
    75085,
    75086,
    75087,
    75088
  );

  script_name(english:"Google Chrome < 43.0.2357.124 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks the version number of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Mac OS X host is
prior to 43.0.2357.124. It is, therefore, affected by multiple
vulnerabilities related to Adobe Flash :

  - An unspecified vulnerability exists that allows an
    attacker to bypass the fix for CVE-2014-5333.
    (CVE-2015-3096)

  - Multiple unspecified flaws exist that allow a remote
    attacker to bypass the same-origin-policy, resulting in
    the disclosure of sensitive information. (CVE-2015-3098,
    CVE-2015-3099, CVE-2015-3102)

  - A remote code execution vulnerability exists due to an
    unspecified stack overflow flaw. (CVE-2015-3100)

  - Multiple use-after-free errors exist that allow an
    attacker to execute arbitrary code. (CVE-2015-3103,
    CVE-2015-3106, CVE-2015-3107)

  - An integer overflow condition exists due to improper
    validation of user-supplied input. A remote attacker can
    exploit this to execute arbitrary code. (CVE-2015-3104)

  - A memory corruption flaw exists due to improper
    validation of user-supplied input. A remote attacker can
    exploit this flaw, via specially crafted flash
    content, to corrupt memory and execute arbitrary code.
    (CVE-2015-3105)

  - An unspecified memory leak exists that allows an
    attacker to bypass the Address Space Layout
    Randomization (ASLR) feature. (CVE-2015-3108)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # http://googlechromereleases.blogspot.com/2015/06/stable-channel-update.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d9b0da1f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome 43.0.2357.124 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-3107");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player Drawing Fill Shader Memory Corruption');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("MacOSX/Google Chrome/Installed");

google_chrome_check_version(fix:'43.0.2357.124', severity:SECURITY_HOLE);
