#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86948);
  script_version("1.9");
  script_cvs_date("Date: 2019/11/22");

  script_cve_id("CVE-2015-5255", "CVE-2015-8052", "CVE-2015-8053");
  script_bugtraq_id(77625, 77626);

  script_name(english:"Adobe ColdFusion Multiple Vulnerabilities (APSB15-29) (credentialed check)");
  script_summary(english:"Checks the hotfix files.");

  script_set_attribute(attribute:"synopsis", value:
"A web-based application running on the remote Windows host is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe ColdFusion running on the remote Windows host
is affected by multiple vulnerabilities :

  - Multiple cross-site scripting (XSS) vulnerabilities
    exist due to a failure to validate input before
    returning it to the user. A remote attacker can exploit
    these to inject arbitrary script or HTML into the user's
    browser session. (CVE-2015-8052, CVE-2015-8053)

  - A flaw exists in BlazeDS related to request handling
    between a user and a server. A remote attacker can
    exploit this, via a crafted XML document, to send HTTP
    traffic to intranet servers, thus allowing the attacker
    to carry out a server-side request forgery attacks.
    (CVE-2015-5255)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/coldfusion/apsb15-29.html");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant hotfixes referenced in Adobe advisory APSB15-29.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-8053");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:coldfusion");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("coldfusion_win_local_detect.nasl");
  script_require_keys("SMB/coldfusion/instance");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("coldfusion_win.inc");
include("global_settings.inc");
include("misc_func.inc");

versions = make_list('10.0.0', '11.0.0');
instances = get_coldfusion_instances(versions); # this exits if it fails

# Check the hotfixes and cumulative hotfixes installed for each
# instance of ColdFusion.
info = NULL;
instance_info = make_list();

foreach name (keys(instances))
{
  info = NULL;
  ver = instances[name];

  if (ver == "10.0.0")
  {
    # CF10 uses an installer for updates so it is less likely (perhaps not possible) to only partially install a hotfix.
    # this means the plugin doesn't need to check for anything in the CFIDE directory, it just needs to check the CHF level
    info = check_jar_chf(name, 18);
  }
  else if (ver == "11.0.0")
  {
    info = check_jar_chf(name,7);
  }

  if (!isnull(info))
    instance_info = make_list(instance_info, info);
}

if (max_index(instance_info) == 0) exit(0, "No vulnerable instances of Adobe ColdFusion were detected.");

port = get_kb_item("SMB/transport");
if (!port) port = 445;

set_kb_item(name:'www/0/XSS', value:TRUE);
if (report_verbosity > 0)
{
  report =
    '\n' + 'Nessus detected the following unpatched instances :' +
    '\n' + join(instance_info, sep:'\n') +
    '\n';
  security_warning(port:port, extra:report);
}
else security_warning(port);
