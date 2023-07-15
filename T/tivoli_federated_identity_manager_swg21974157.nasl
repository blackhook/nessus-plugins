#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88090);
  script_version("1.9");
  script_cvs_date("Date: 2019/11/20");

  script_cve_id("CVE-2015-4959");
  script_bugtraq_id(80376);

  script_name(english:"IBM Tivoli Federated Identity Manager 6.2.2 < 6.2.2 FP16 XSS (swg21974157)");
  script_summary(english:"Checks the version of IBM Tivoli Federated Identity Manager.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Tivoli Federated Identity Manager installed on the
remote Windows host is 6.2.2.x prior to 6.2.2.16. It is, therefore,
affected by a cross-site scripting vulnerability due to improper
validation of user-supplied input. An unauthenticated, remote attacker
can exploit this, via a crafted URL, to execute arbitrary script code
in a user's browser session.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21974157");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Tivoli Federated Identity Manager 6.2.2 FP16 (6.2.2.16)
or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-4959");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_federated_identity_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tivoli_federated_identity_manager_installed.nbin");
  script_require_keys("installed_sw/IBM Tivoli Federated Identity Manager");
  script_require_ports(139, 445);

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include("install_func.inc");

app_name = 'IBM Tivoli Federated Identity Manager';
install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);

version = install['version'];
path    = install['path'];

fix = '';
if (version =~ '^6\\.2\\.2($|\\.)' && ver_compare(ver:version, fix:'6.2.2.16', strict:FALSE) < 0) fix = '6.2.2.16';
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);

set_kb_item(name:"www/0/XSS", value:TRUE);

port = get_kb_item("SMB/transport");
if(isnull(port)) port = 445;

if (report_verbosity > 0)
{
  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix + '\n';
  security_warning(port:port, extra:report);
}
else security_warning(port);
