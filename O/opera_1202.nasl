#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61732);
  script_version("1.7");
  script_cvs_date("Date: 2019/12/04");

  script_cve_id("CVE-2012-6460");
  script_bugtraq_id(55301);

  script_name(english:"Opera < 12.02 Truncated Dialog Vulnerability");
  script_summary(english:"Checks version number of Opera");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by a
truncated dialog vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Opera installed on the remote host is earlier than
12.02 and is, therefore, reportedly affected by a truncated dialog
vulnerability.

Certain user actions, when combined with specially crafted web pages,
can cause displayed dialog boxes to be too small thus allowing the
dialog buttons to be hidden. A user may be tricked into clicking
what appear to be elements on the underlying page, but are actually
the hidden dialog buttons. This can allow arbitrary code execution to
occur.");
  script_set_attribute(attribute:"see_also", value:"http://web.archive.org/web/20130223095132/http://www.opera.com/support/kb/view/1028/");
  script_set_attribute(attribute:"see_also", value:"http://web.archive.org/web/20170911062017/http://www.opera.com:80/docs/changelogs/unified/1202/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Opera 12.02 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-6460");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:opera:opera_browser");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("opera_installed.nasl");
  script_require_keys("SMB/Opera/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

path = get_kb_item_or_exit("SMB/Opera/Path");
version = get_kb_item_or_exit("SMB/Opera/Version");
version_ui = get_kb_item("SMB/Opera/Version_UI");

if (isnull(version_ui)) version_report = version;
else version_report = version_ui; 

fixed_version = "12.2.1578.0";

# Check if we need to display full version info in case of Alpha/Beta/RC
major_minor = eregmatch(string:version, pattern:"^([0-9]+\.[0-9]+)");
if (major_minor[1] == "12.02")
{
  fixed_version_report = fixed_version;
  version_report = version;
}
else fixed_version_report = "12.02";

if (ver_compare(ver:version, fix:fixed_version) == -1)
{
  port = get_kb_item("SMB/transport");
  if (report_verbosity > 0)
  {
    report = 
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version_report +
      '\n  Fixed version     : ' + fixed_version_report +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Opera", version_report, path);
