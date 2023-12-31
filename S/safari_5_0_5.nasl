#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(53411);
  script_version("1.7");
  script_cvs_date("Date: 2018/07/27 18:38:15");

  script_cve_id("CVE-2011-1290", "CVE-2011-1344");
  script_bugtraq_id(46822, 46849);

  script_name(english:"Safari < 5.0.5 Multiple Vulnerabilities");
  script_summary(english:"Checks Safari's version number");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host contains a web browser that is affected by several
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Safari installed on the remote Windows host is earlier
than 5.0.5.  It therefore is potentially affected by several issues :

  - An integer overflow issue in the handling of nodesets
    could lead to a crash or arbitrary code execution.
    (CVE-2011-1290)

  - A use-after-free issue in the handling of text nodes
    could lead to a crash or arbitrary code execution.
    (CVE-2011-1344)"
  );
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT4596");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2011/Apr/msg00002.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Safari 5.0.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:safari");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2018 Tenable Network Security, Inc.");

  script_dependencies("safari_installed.nasl");
  script_require_keys("SMB/Safari/FileVersion");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


version = get_kb_item_or_exit("SMB/Safari/FileVersion");

version_ui = get_kb_item("SMB/Safari/ProductVersion");
if (isnull(version_ui)) version_ui = version;

if (ver_compare(ver:version, fix:"5.33.21.1") == -1)
{
  if (report_verbosity > 0)
  {
    path = get_kb_item("SMB/Safari/Path");
    if (isnull(path)) path = "n/a";

    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version_ui +
      '\n  Fixed version     : 5.0.5 (7533.21.1)\n';
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
else exit(0, "The remote host is not affected since Safari " + version_ui + " is installed.");
