#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62588);
  script_version("1.11");
  script_cvs_date("Date: 2019/12/04");

  script_cve_id("CVE-2012-4192", "CVE-2012-4193");
  script_bugtraq_id(56154, 56155);

  script_name(english:"Firefox 10.x < 10.0.9 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Firefox 10.x is potentially affected by the
following security issues :

  - An unspecified error exists that can allow attackers to
    bypass the 'Same Origin Policy' and access the
    'Location' object. (CVE-2012-4192)

  - An error exists related to 'security wrappers' and the
    function 'defaultValue()' that can allow cross-site
    scripting attacks. (CVE-2012-4193)");
  # http://www.thespanner.co.uk/2012/10/10/firefox-knows-what-your-friends-did-last-summer/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8993e6b4");
  # https://blog.mozilla.org/security/2012/10/10/security-vulnerability-in-firefox-16/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dc43f3c3");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-89/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 10.0.9 ESR or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-4193");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/17");

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
port = get_kb_item_or_exit("SMB/transport"); 

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:TRUE, fix:'10.0.9', min:'10.0', severity:SECURITY_HOLE, xss:TRUE);