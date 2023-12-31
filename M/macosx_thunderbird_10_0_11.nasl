#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62995);
  script_version("1.18");
  script_cvs_date("Date: 2019/12/04");

  script_cve_id(
    "CVE-2012-4201",
    "CVE-2012-4202",
    "CVE-2012-4207",
    "CVE-2012-4209",
    "CVE-2012-4214",
    "CVE-2012-4215",
    "CVE-2012-4216",
    "CVE-2012-5829",
    "CVE-2012-5830",
    "CVE-2012-5833",
    "CVE-2012-5835",
    "CVE-2012-5839",
    "CVE-2012-5840",
    "CVE-2012-5841",
    "CVE-2012-5843"
  );
  script_bugtraq_id(
    56612,
    56614,
    56618,
    56628,
    56629,
    56631,
    56632,
    56633,
    56634,
    56635,
    56636,
    56637,
    56641,
    56642,
    56643
  );

  script_name(english:"Thunderbird 10.x < 10.0.11 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks version of Thunderbird");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a mail client that is potentially
affected by several vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Thunderbird 10.x is potentially affected by
the following security issues :
  
  - Several memory safety bugs exist in the browser engine 
    used in Mozilla-based products that could be exploited 
    to execute arbitrary code. (CVE-2012-5843)

  - An error exists in the method
    'image::RasterImage::DrawFrameTo' related to GIF images
    that could allow a heap-based buffer overflow, leading to
    arbitrary code execution. (CVE-2012-4202)

  - Errors exist related to 'evalInSandbox', 'HZ-GB-2312'
    charset, frames and the 'location' object, and
    'cross-origin wrappers' that could allow cross-site
    scripting (XSS) attacks. (CVE-2012-4201,
    CVE-2012-4207, CVE-2012-4209, CVE-2012-5841)

  - Various use-after-free, out-of-bounds read and buffer
    overflow errors exist that could potentially lead to
    arbitrary code execution. (CVE-2012-4214, CVE-2012-4215,
    CVE-2012-4216, CVE-2012-5829, CVE-2012-5830,
    CVE-2012-5833, CVE-2012-5835, CVE-2012-5839,
    CVE-2012-5840)

Please note the 10.x ESR branch will be unsupported as of 02/13/2013.
Only the 17.x ESR branch will receive security updates after that
date.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-91/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-92/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-93/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-100/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-101/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-103/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-105/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-106/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Thunderbird 10.0.11 ESR or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-5843");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_thunderbird_installed.nasl");
  script_require_keys("MacOSX/Thunderbird/Installed");

  exit(0);
}

include("mozilla_version.inc");
kb_base = "MacOSX/Thunderbird";
get_kb_item_or_exit(kb_base+"/Installed");

version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);
path = get_kb_item_or_exit(kb_base+"/Path", exit_code:1);

mozilla_check_version(product:'thunderbird', version:version, path:path, fix:'10.0.11', min:'10.0', severity:SECURITY_HOLE, xss:TRUE);
