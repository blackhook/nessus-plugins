#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55287);
  script_version("1.21");
  script_cvs_date("Date: 2018/07/16 14:09:14");

  script_cve_id(
    "CVE-2011-0083",
    "CVE-2011-0085",
    "CVE-2011-2362",
    "CVE-2011-2363",
    "CVE-2011-2364",
    "CVE-2011-2365",
    "CVE-2011-2371",
    "CVE-2011-2373",
    "CVE-2011-2374",
    "CVE-2011-2376",
    "CVE-2011-2377"
  );
  script_bugtraq_id(
    48357,
    48358,
    48360,
    48361,
    48365,
    48366,
    48367,
    48368,
    48369,
    48372,
    48373,
    48376
  );
  script_xref(name:"EDB-ID", value:"17974");
  script_xref(name:"EDB-ID", value:"17976");
  script_xref(name:"EDB-ID", value:"18531");
  script_xref(name:"Secunia", value:"44982");

  script_name(english:"Firefox 3.6 < 3.6.18 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Firefox 3.6 is earlier than 3.6.18.  Such
versions are potentially affected by the following security issues :

  - Multiple memory safety issues can lead to application
    crashes and possibly remote code execution.
    (CVE-2011-2374, CVE-2011-2376, CVE-2011-2364,
    CVE-2011-2365)

  - A use-after-free issue when viewing XUL documents with
    scripts disabled could lead to code execution.
    (CVE-2011-2373)

  - A memory corruption issue due to multipart / 
    x-mixed-replace images could lead to memory corruption.
    (CVE-2011-2377)

  - When a JavaScript Array object has its length set to an
    extremely large value, the iteration of array elements
    that occurs when its reduceRight method is called could
    result in code execution due to an invalid index value
    being used. (CVE-2011-2371)

  - Multiple dangling pointer vulnerabilities could lead to
    code execution. (CVE-2011-0083, CVE-2011-2363,
    CVE-2011-0085)

  - An error in the way cookies are handled could lead to
    information disclosure. (CVE-2011-2362)");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5694f54a");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2011-19/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2011-20/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2011-21/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2011-22/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2011-23/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2011-24/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-223/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-224/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-225/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Firefox 3.6.18 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mozilla Firefox Array.reduceRight() Integer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2018 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport"); 

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'3.6.18', min:'3.6', severity:SECURITY_HOLE);