#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83368);
  script_version("1.15");
  script_cvs_date("Date: 2019/11/22");

  script_cve_id(
    "CVE-2015-3044",
    "CVE-2015-3077",
    "CVE-2015-3078",
    "CVE-2015-3079",
    "CVE-2015-3080",
    "CVE-2015-3082",
    "CVE-2015-3083",
    "CVE-2015-3084",
    "CVE-2015-3085",
    "CVE-2015-3086",
    "CVE-2015-3087",
    "CVE-2015-3088",
    "CVE-2015-3089",
    "CVE-2015-3090",
    "CVE-2015-3091",
    "CVE-2015-3092",
    "CVE-2015-3093"
  );
  script_bugtraq_id(
    74605,
    74608,
    74609,
    74610,
    74612,
    74614,
    74616,
    74617
  );

  script_name(english:"Google Chrome < 42.0.2311.152 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks the version number of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Mac OS X host is
prior to 42.0.2311.152. It is, therefore, affected by multiple
vulnerabilities related to Adobe Flash :

  - An unspecified security bypass flaw exists that allows
    an attacker to disclose sensitive information.
    (CVE-2015-3044)

  - Multiple unspecified type confusion flaws exist that
    allow an attacker to execute arbitrary code.
    (CVE-2015-3077, CVE-2015-3084, CVE-2015-3086)

  - Multiple memory corruption flaws exist due to improper
    validation of user-supplied input. A remote attacker can
    exploit these flaws, via specially crafted flash
    content, to corrupt memory and execute arbitrary code.
    (CVE-2015-3078, CVE-2015-3089, CVE-2015-3090,
    CVE-2015-3093)

  - An unspecified security bypass exists that allows a
    context-dependent attacker to disclose sensitive
    information. (CVE-2015-3079)

  - An unspecified use-after-free error exists that allows
    an attacker to execute arbitrary code. (CVE-2015-3080)

  - Multiple validation bypass vulnerabilities exists that
    allow an attacker to lead to write arbitrary data to the
    file system. (CVE-2015-3082, CVE-2015-3083,
    CVE-2015-3085)

  - An integer overflow condition exists due to improper
    validation of user-supplied input. This allows a
    context-dependent attacker to execute arbitrary code.
    (CVE-2015-3087)

  - A heap-based buffer overflow condition exists due to
    improper validation of user-supplied input. A remote
    attacker can exploit this to execute arbitrary code.
    (CVE-2015-3088)

  - Multiple unspecified memory leaks exist that allow an
    attacker to bypass the Address Space Layout
    Randomization (ASLR) feature. (CVE-2015-3091,
    CVE-2015-3092)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # http://googlechromereleases.blogspot.com/2015/05/stable-channel-update.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7417f6c2");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-09.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome 42.0.2311.152 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-3093");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player ShaderJob Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/12");

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

google_chrome_check_version(fix:'42.0.2311.152', severity:SECURITY_HOLE);
