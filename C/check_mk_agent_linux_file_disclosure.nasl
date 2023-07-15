#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101088);
  script_version("2.8");
  script_cvs_date("Date: 2019/11/14");

  script_cve_id("CVE-2014-0243");
  script_bugtraq_id(67674);

  script_name(english:"Check_MK Agent for Linux 1.2.3i < 1.2.5i3 Arbitrary File Disclosure");
  script_summary(english:"Checks for the product and version in the about page.");

  script_set_attribute(attribute:"synopsis", value:
"An IT monitoring application running on the remote host is affected by
an arbitrary file disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Check_MK running on the remote web server is 1.2.3i
prior to 1.2.5i3. It is, therefore, affected by a flaw due to the
/var/lib/check_mk_agent/job directory creating temporary files with
insufficiently secure permissions. A local attacker can exploit this
issue by creating a symbolic link in the directory so that it points
to a file the attacker normally would not have access to (e.g.,
/etc/shadow). Since the agent expects output from jobs using the
mk-job Tool in that directory, it will output the content of all files
in the directory on TCP port 6556 by default.");
  script_set_attribute(attribute:"see_also", value:"https://www.foxmole.com/advisories/lse-2014-05-21.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/532224");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Check_MK version 1.2.5i3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:X");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0243");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:check_mk_project:check_mk");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("check_mk_detect.nasl");
  script_require_keys("Check_MK/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("vcf.inc");
include("vcf_extras.inc");

port = get_kb_item_or_exit("Check_MK/Installed");
kb_ver = "Check_MK/" + port + "/Version";
os = get_kb_item("Check_MK/" + port + "/AgentOS");

if(os !~ "Linux") audit(AUDIT_OS_NOT, "linux");

vcf::check_mk::initialize();
app = vcf::get_app_info(app:"Check_MK Agent", port:port, kb_ver:kb_ver, service:TRUE);

constraints = [{"min_version" : "1.2.3i", "fixed_version" : "1.2.5i3"}];

vcf::check_version_and_report(app_info:app, constraints:constraints, severity:SECURITY_NOTE, strict:FALSE);
