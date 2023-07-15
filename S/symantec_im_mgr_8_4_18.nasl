#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(56378);
  script_version("1.8");
  script_cvs_date("Date: 2018/11/15 20:50:29");

  script_cve_id("CVE-2011-0552", "CVE-2011-0553", "CVE-2011-0554");
  script_bugtraq_id(49738, 49739, 49742);
  script_xref(name:"Secunia", value:"43157");

  script_name(english:"Symantec IM Manager < 8.4.18 Multiple Vulnerabilities (SYM11-012)");
  script_summary(english:"Checks version of Symantec IM Manager");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web application on the remote Windows host has multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Symantec IM Manager running on the remote host is
earlier than 8.4.18.  Such versions are affected by the following
vulnerabilities in the management console :

  - Multiple XSS. (CVE-2011-0552)

  - An unspecified SQL injection. (CVE-2011-0553)

  - An unspecified code injection. (CVE-2011-0554)"
  );
  script_set_attribute(attribute:"see_also",value:"https://www.zerodayinitiative.com/advisories/ZDI-11-294/");
  # https://support.symantec.com/en_US/article.SYMSA1235.html
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?1b7c02d7");
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Symantec IM Manager 8.4.18 (build 8.4.1405) or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/09/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/03");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:im_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2018 Tenable Network Security, Inc.");

  script_dependencies("symantec_im_mgr_installed.nasl");
  script_require_keys("SMB/Symantec/im_mgr/Build");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


build = get_kb_item_or_exit('SMB/Symantec/im_mgr/Build');
build_pat = "^([0-9]+\.[0-9]+\.[0-9]+)\.[0-9]+$";
if (match = eregmatch(pattern:build_pat, string:build))
  build = match[1];
else
  exit(1, "Error parsing IM Mgr build (" + build + ").");

fixed_build = '8.4.1405';

if (ver_compare(ver:build, fix:fixed_build) == -1)
{
  set_kb_item(name:'www/0/XSS', value:TRUE);
  set_kb_item(name:'www/0/SQLInjection', value:TRUE);
  
  port = get_kb_item("SMB/transport");

  if (report_verbosity > 0)
  {
    path = get_kb_item('SMB/Symantec/im_mgr/Path');
    if (isnull(path)) path = 'n/a';

    report = '\n  Path                    : '+path+
             '\n  Installed build version : '+build+
             '\n  Fixed build version     : '+fixed_build+'\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else exit(0, "Symantec IM Manager build version "+build+" is installed and not affected.");
