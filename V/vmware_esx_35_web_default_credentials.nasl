#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(121350);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/31");

  script_name(english:"VMware ESX / ESXi Web-Based Datastore Browser Default Credentials");
  script_summary(english:"Try logging into the ESX / ESXi web interface using default credentials.");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESX / ESXi host is protected using a known set of credentials.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to log in to the remote VMware ESX / ESXi Web-Based
Datastore Browser using a default set of administrative credentials.
A remote attacker could utilize these credentials to access virtual
machine and virtual disk files.");
  script_set_attribute(attribute:"solution", value:"Change passwords on any default accounts.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"default credentials");

  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_vsphere_detect.nbin");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Host/VMware/vsphere");

  exit(0);
}

include('http.inc');
include('debug.inc');

var port = get_kb_item_or_exit("Host/VMware/vsphere");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

var username = "root";
var password = "";

var item = "/folder?dcPath=ha-datacenter";
var url = build_url(port:port, qs:item);

var res = http_send_recv3(
  method:'GET',
  item:item,
  port:port,
  username:username,
  password:password,
  exit_on_fail:TRUE
);
dbg::detailed_log(lvl:1, src:SCRIPT_NAME, msg:'GET /folder?dcPath=ha-datacenter returned the below:\n' + res[0] + '\n' + res[2] + '\n');

if (("Unauthorized" >< res[0] || "Authentication Required" >< res[2]) || res[0] !~ "^HTTP/[0-9.]+ 200") 
  audit(AUDIT_WEB_APP_NOT_AFFECTED, "VMware ESX / ESXi Web-Based Datastore Browser", url);

var report =
  '\n' + 'It is possible to log into the VMware ESX / ESXi Web-Based Datastore Browser at the' +
  '\n' + 'following URL :' +
  '\n' +
  '\n' + url +
  '\n' +
  '\n' + 'with these credentials :' +
  '\n  Username : ' + username +
  '\n  Password : ' + password +
  '\n';

security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
