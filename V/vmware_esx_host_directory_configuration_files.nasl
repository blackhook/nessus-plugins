#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(121351);
  script_version("1.1");
  script_cvs_date("Date: 2019/01/24 15:01:01");

  script_name(english:"VMware ESX / ESXi host Directory Configuration Files Information Disclosure");
  script_summary(english:"Finds /host directory containing VMware ESX / ESXi configuration files.");

  script_set_attribute(attribute:"synopsis", value:
"Configuration files are accessible on the remote VMware ESX / ESXi host.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESX / ESXi host is making available configuration
files in the /host directory on the web interface. These contain
sensitive host configuration information and should not be remotely
accessible.");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/200.html");
  script_set_attribute(attribute:"solution", value:
"Disable or secure /host web directory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"score from an in depth analysis done by Tenable");

  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/24");

  script_set_attribute(attribute:"plugin_type", value: "remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_vsphere_detect.nbin");
  script_require_ports("Host/VMware/vsphere");
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("audit.inc");

port = get_kb_item_or_exit("Host/VMware/vsphere");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

res = http_send_recv3(method:'GET', item:"/host", port:port, username:"root", password:"", exit_on_fail:TRUE);

if ("Configuration files" >< res[2])
{
  report = '\n' +
'  Nessus was able to access VMware ESX / ESXi configuration files\n' +
'  using the following request:\n' +
'    ' + build_url(port:port, qs:"/host", username:"root", password:"") + '\n' +
'\n' +
'  The following configuration files are accessible on the remote host:\n';
  lines = split(res[2]);
  foreach line (lines)
  {
    matches = pregmatch(string:line, pattern:'<td><a href=".*">(.*)</a>');
    if (isnull(matches)) continue;

    filename = matches[1];
    report += "    " + filename + '\n';
  }

  security_report_v4(severity:SECURITY_WARNING, port:port, extra:report);
  exit(0);
}
else audit(AUDIT_WEB_FILES_NOT, "VMware ESX / ESXi Configuration", port);
