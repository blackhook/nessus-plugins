#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62744);
  script_version("1.13");
  script_cvs_date("Date: 2019/12/04");

  script_cve_id("CVE-2012-4194", "CVE-2012-4195", "CVE-2012-4196");
  script_bugtraq_id(56301, 56302, 56306);

  script_name(english:"Firefox < 16.0.2 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Firefox is earlier than 16.0.2 and is,
therefore, potentially affected by the following security issues :

  - The true value of 'window.location' can be shadowed by
    user content through the use of the 'valueOf' method,
    which can be combined with some plugins to perform
    cross-site scripting attacks. (CVE-2012-4194)

  - The 'CheckURL' function of 'window.location' can be
    forced to return the wrong calling document and
    principal, allowing a cross-site scripting attack.
    (CVE-2012-4195)

  - It is possible to use property injection by prototype to
    bypass security wrapper protections on the 'Location'
    object, allowing the cross-origin reading of the
    'Location' object. (CVE-2012-4196)");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-90/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 16.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-4195");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include("mozilla_version.inc");

port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'16.0.2', severity:SECURITY_WARNING, xss:TRUE);
