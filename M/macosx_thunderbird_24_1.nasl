#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70713);
  script_version("1.8");
  script_cvs_date("Date: 2019/11/27");

  script_cve_id(
    "CVE-2013-1739",
    "CVE-2013-5590",
    "CVE-2013-5591",
    "CVE-2013-5592",
    "CVE-2013-5593",
    "CVE-2013-5595",
    "CVE-2013-5596",
    "CVE-2013-5597",
    "CVE-2013-5599",
    "CVE-2013-5600",
    "CVE-2013-5601",
    "CVE-2013-5602",
    "CVE-2013-5603",
    "CVE-2013-5604"
  );
  script_bugtraq_id(
    62966,
    63405,
    63415,
    63416,
    63417,
    63418,
    63420,
    63421,
    63422,
    63423,
    63424,
    63427,
    63428,
    63429,
    63430
  );

  script_name(english:"Thunderbird < 24.1 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks version of Thunderbird");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a mail client that is potentially
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Thunderbird is earlier than 24.1 and is,
therefore, potentially affected by the following vulnerabilities :

  - The implementation of Network Security Services (NSS)
    does not ensure that data structures are initialized,
    which could result in a denial of service or disclosure
    of sensitive information. (2013-1739)

  - Memory issues exist in the browser engine that could
    result in a denial of service or arbitrary code
    execution. (CVE-2013-5590, CVE-2013-5591, CVE-2013-5592)

  - Arbitrary HTML content can be put into 'select'
    elements.  This can be used to spoof the displayed
    address bar, leading to clickjacking and other spoofing
    attacks. (CVE-2013-5593)

  - Memory issues exist in the JavaScript engine that could
    result in a denial of service or arbitrary code
    execution. (CVE-2013-5595, CVE-2013-5602)

  - A race condition exists during image collection on large
    web pages that could result in a denial of service or
    arbitrary code execution. (CVE-2013-5596)

  - Multiple use-after-free vulnerabilities exist that could
    result in a denial of service or arbitrary code
    execution. (CVE-2013-5597, CVE-2013-5599, CVE-2013-5600,
    CVE-2013-5601, CVE-2013-5603)

  - A stack-based buffer overflow in
    txXPathNodeUtils::getBaseURI is possible due to
    uninitialized data during XSLT processing.
    (CVE-2013-5604)");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-93/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-94/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-95/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-96/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-97/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-98/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-100/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-101/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-102/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Thunderbird 24.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-5603");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_thunderbird_installed.nasl");
  script_require_keys("MacOSX/Thunderbird/Installed");

  exit(0);
}

include("mozilla_version.inc");

kb_base = "MacOSX/Thunderbird";
get_kb_item_or_exit(kb_base+"/Installed");

version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);
path = get_kb_item_or_exit(kb_base+"/Path", exit_code:1);

if (get_kb_item(kb_base + '/is_esr')) exit(0, 'The Mozilla Thunderbird install is in the ESR branch.');

mozilla_check_version(product:'thunderbird', version:version, path:path, esr:FALSE, fix:'24.1', severity:SECURITY_HOLE, xss:FALSE);
