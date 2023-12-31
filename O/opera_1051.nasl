#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(45121);
  script_version("1.11");
  script_cvs_date("Date: 2018/11/15 20:50:27");

  script_cve_id("CVE-2010-1310", "CVE-2010-1349");
  script_bugtraq_id(38519, 38892);
  script_xref(name:"Secunia", value:"38820");

  script_name(english:"Opera < 10.51 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Opera");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
issues."
  );
  script_set_attribute(attribute:"description", value:
"The version of Opera installed on the remote host is earlier than
10.51.  Such versions are potentially affected by multiple issues :

  - Large values in the HTTP Content-Length header can be
    used to execute arbitrary code. (948)

  - XSLT can be used to retrieve random contents of 
    unrelated documents. (949)"
  );
  script_set_attribute(attribute:"see_also", value:"http://web.archive.org/web/20130225215234/http://www.opera.com/support/kb/view/948/");
  script_set_attribute(attribute:"see_also", value:"http://web.archive.org/web/20130225211617/http://www.opera.com/support/kb/view/949/");
  script_set_attribute(attribute:"see_also", value:"http://web.archive.org/web/20170713152042/http://www.opera.com:80/docs/changelogs/windows/1051/");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e494cf3e");
  script_set_attribute(attribute:"solution", value:"Upgrade to Opera 10.51 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/22");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:opera:opera_browser");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2018 Tenable Network Security, Inc.");

  script_dependencies("opera_installed.nasl");
  script_require_keys("SMB/Opera/Version");

  exit(0);
}

include("global_settings.inc");

version_ui = get_kb_item("SMB/Opera/Version_UI");
version = get_kb_item("SMB/Opera/Version");
if (isnull(version)) exit(1, "The 'SMB/Opera/Version' KB item is missing.");

if (isnull(version_ui)) version_report = version;
else version_report = version_ui;

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] < 10 ||
  (ver[0] == 10 && ver[1] < 51)
)
{
  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "Opera ", version_report, " is currently installed on the remote host.\n"
    );
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(port:get_kb_item("SMB/transport"));
  exit(0);
}
else exit(0, "The host is not affected since Opera "+version_report+" is installed.");
