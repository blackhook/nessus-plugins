#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77500);
  script_version("1.8");
  script_cvs_date("Date: 2019/11/25");

  script_cve_id(
    "CVE-2014-1553",
    "CVE-2014-1554",
    "CVE-2014-1562",
    "CVE-2014-1563",
    "CVE-2014-1564",
    "CVE-2014-1565",
    "CVE-2014-1567"
  );
  script_bugtraq_id(
    69519,
    69520,
    69521,
    69523,
    69524,
    69525,
    69526
  );

  script_name(english:"Firefox < 32.0 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox installed on the remote host is a version prior
to 32.0. It is, therefore, affected by the following vulnerabilities :

  - Multiple memory safety flaws exist within the browser
    engine. Exploiting these, an attacker can cause a denial
    of service or execute arbitrary code. (CVE-2014-1553,
    CVE-2014-1554, CVE-2014-1562)

  - A use-after-free vulnerability exists due to improper
    cycle collection when processing animated SVG content.
    A remote attacker can exploit this to cause a denial of
    service or execute arbitrary code. (CVE-2014-1563)

  - Memory is not properly initialized during GIF rendering.
    Using a specially crafted web script, a remote attacker
    can exploit this to acquire sensitive information from
    the process memory. (CVE-2014-1564)

  - The Web Audio API contains a flaw where audio timelines
    are properly created. Using specially crafted API calls,
    a remote attacker can exploit this to acquire sensitive
    information from the process memory or cause a denial of
    service. (CVE-2014-1565)

  - A use-after-free vulnerability exists due to improper
    handling of text layout in directionality resolution.
    A remote attacker can exploit this to execute arbitrary
    code. (CVE-2014-1567)");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/533357/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/security/announce/2014/mfsa2014-67.html");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/security/announce/2014/mfsa2014-68.html");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/security/announce/2014/mfsa2014-69.html");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/security/announce/2014/mfsa2014-70.html");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-71/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/security/announce/2014/mfsa2014-72.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 32.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-1563");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include("mozilla_version.inc");

port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'32.0', severity:SECURITY_HOLE, xss:FALSE);
