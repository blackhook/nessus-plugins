#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57775);
  script_version("1.21");
  script_cvs_date("Date: 2018/07/14  1:59:36");

  script_cve_id(
    "CVE-2011-3659",
    "CVE-2012-0442",
    "CVE-2012-0443",
    "CVE-2012-0444",
    "CVE-2012-0445",
    "CVE-2012-0446",
    "CVE-2012-0447",
    "CVE-2012-0449"
  );
  script_bugtraq_id(
    51752,
    51753,
    51754,
    51755,
    51756,
    51757,
    51765
  );

  script_name(english:"Thunderbird 9.x Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks version of Thunderbird");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains an email client that is potentially
affected by several vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Thunderbird 9.x is potentially affected by
the following security issues :

  - A use-after-free error exists related to removed
    nsDOMAttribute child nodes.(CVE-2011-3659)

  - Various memory safety issues exist. (CVE-2012-0442,
    CVE-2012-0443)

  - Memory corruption errors exist related to the
    decoding of Ogg Vorbis files and processing of
    malformed XSLT stylesheets. (CVE-2012-0444,
    CVE-2012-0449)

  - The HTML5 frame navigation policy can be violated by
    allowing an attacker to replace a sub-frame in another
    domain's document. (CVE-2012-0445)

  - Scripts in frames are able to bypass security
    restrictions in XPConnect. This bypass can allow
    malicious websites to carry out cross-site scripting
    attacks. (CVE-2012-0446)

  - An information disclosure issue exists when
    uninitialized memory is used as padding when encoding
    icon images. (CVE-2012-0447)"
  );
  script_set_attribute(attribute:"see_also", value:"http://dev.w3.org/html5/spec/browsers.html#security-nav");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-01/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-03/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-04/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-05/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-06/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-07/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-08/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Thunderbird 10.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox 8/9 AttributeChildRemoved() Use-After-Free');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/01/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2018 Tenable Network Security, Inc.");

  script_dependencies("macosx_thunderbird_installed.nasl");
  script_require_keys("MacOSX/Thunderbird/Installed");

  exit(0);
}

include("mozilla_version.inc");
kb_base = "MacOSX/Thunderbird";
get_kb_item_or_exit(kb_base+"/Installed");

version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);
path = get_kb_item_or_exit(kb_base+"/Path", exit_code:1);

mozilla_check_version(product:'thunderbird', version:version, path:path, fix:'10.0', skippat:'^3\\.6\\.', severity:SECURITY_HOLE, xss:TRUE);
