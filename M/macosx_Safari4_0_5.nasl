#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(45044);
  script_version("1.17");
  script_cvs_date("Date: 2018/07/14  1:59:35");

  script_cve_id(
    "CVE-2010-0044",
    "CVE-2010-0046",
    "CVE-2010-0047",
    "CVE-2010-0048",
    "CVE-2010-0049",
    "CVE-2010-0050",
    "CVE-2010-0051",
    "CVE-2010-0052",
    "CVE-2010-0053",
    "CVE-2010-0054"
  );
  script_bugtraq_id(
    38675,
    38684,
    38685,
    38686,
    38687,
    38688,
    38689,
    38690,
    38691,
    38692
  );

  script_name(english:"Mac OS X : Apple Safari < 4.0.5");
  script_summary(english:"Check the Safari SourceVersion");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host contains a web browser that is affected by several
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Apple Safari installed on the remote Mac OS X host is
earlier than 4.0.5.  As such, it is potentially affected by several
issues :

  - An implementation issue in the handling of cookies set
    by RSS and Atom feeds could result in a cookie being
    set when visiting or updating a feed even if Safari is
    configured to block cookies via the 'Accept Cookies'
    preference. (CVE-2010-0044)

  - A memory corruption issue in WebKit's handling of CSS
    format() arguments could lead to a crash or arbitrary
    code execution. (CVE-2010-0046)

  - A use-after-free issue in the handling of HTML object
    element fallback content could lead to a crash or
    arbitrary code execution. (CVE-2010-0047)

  - A use-after-free issue in WebKit's parsing of XML
    documents could lead to a crash or arbitrary code
    execution. (CVE-2010-0048)

  - A use-after-free issue in the handling of HTML elements
    containing right-to-left displayed text could lead to a
    crash or arbitrary code execution. (CVE-2010-0049)

  - A use-after-free issue in WebKit's handling of
    incorrectly nested HTML tags could lead to a crash or
    arbitrary code execution. (CVE-2010-0050)

  - An implementation issue in WebKit's handling of cross-
    origin stylesheet requests when visiting a malicious
    website could result in disclosure of the content of
    protected resources on another website. (CVE-2010-0051)

  - A use-after-free issue in WebKit's handling of
    callbacks for HTML elements could lead to a crash or
    arbitrary code execution. (CVE-2010-0052)

  - A use-after-free issue in the rendering of content with
    a CSS display property set to 'run-in' could lead to a
    crash or arbitrary code execution. (CVE-2010-0053)

  - A use-after-free issue in WebKit's handling of HTML
    image elements could lead to a crash or arbitrary code
    execution. (CVE-2010-0054)"
  );
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT4070");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2010/Mar/msg00000.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/advisories/19255");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apple Safari 4.0.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:safari");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2010-2018 Tenable Network Security, Inc.");

  script_dependencies("macosx_Safari31.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/uname", "Host/MacOSX/Version", "MacOSX/Safari/Installed");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

uname = get_kb_item_or_exit("Host/uname");
if (!egrep(pattern:"Darwin.* (8\.|9\.[0-8]\.|10\.)", string:uname)) audit(AUDIT_OS_NOT, "Mac OS X 10.4 / 10.5 / 10.6");


get_kb_item_or_exit("MacOSX/Safari/Installed");
path = get_kb_item_or_exit("MacOSX/Safari/Path", exit_code:1);
version = get_kb_item_or_exit("MacOSX/Safari/Version", exit_code:1);

fixed_version = "4.0.5";

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "Safari", version);
