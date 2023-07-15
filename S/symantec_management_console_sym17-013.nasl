#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104972);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-15527");
  script_bugtraq_id(101743);
  script_xref(name:"IAVB", value:"2017-B-0164");

  script_name(english:"Symantec Management Console File Name Handling Path Traversal Remote Access (SYM17-013)");
  script_summary(english:"Checks version of Symantec Management Console.");

  script_set_attribute(attribute:"synopsis", value:
"The Symantec Management Console on the target host is affected by a
Management Console directory traversal vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Symantec Manager Console running on the remote host is
earlier than ITM 8.1 RU4 and is therefore affected by a directory
traversal vulnerability in the Management Console that allows
unauthorized access to the file system.");
  # https://support.symantec.com/en_US/article.SYMSA1421.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b81b7956");
  # https://www.scmagazine.com/symantec-security-updates-management-console-directory-traversal/article/708985/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?81624649");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Management Console ITMS 8.1 RU4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-15527");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:altiris_it_management_suite");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("symantec_management_console_detect.nbin");
  script_require_keys("installed_sw/Symantec Management Console", "SMB/Registry/Enumerated");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");
include("smb_func.inc");
include("audit.inc");

# release notes https://support.symantec.com/en_US/article.DOC10690.html
fixed_builds = make_array("8.1.0.0", "8.1.5641.0");

install = get_single_install(app_name:"Symantec Management Console", exit_if_unknown_ver:TRUE);
build = install["version"];
path = install["path"];

foreach product_branch (keys(fixed_builds))
{
  # Check if the version is vulnerable, but make sure it's the right major/minor version too
  if (ver_compare(fix:product_branch, ver:build) >= 0 &&
      ver_compare(fix:fixed_builds[product_branch], ver:build) == -1)

  fixed_build = fixed_builds[product_branch];
}

if (! empty_or_null(fixed_build))
{

  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (isnull(path)) path = 'n/a';

  report = '\n  Path                    : '+path+
           '\n  Installed build version : '+build+
           '\n  Fixed build version     : '+fixed_build+'\n';
  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
}
else
  audit(AUDIT_INST_VER_NOT_VULN, "Symantec Management Console",  build);
