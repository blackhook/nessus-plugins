#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(121352);
  script_version("1.3");
  script_cvs_date("Date: 2019/09/30 10:58:13");

  script_name(english:"VMware ESX / ESXi Remotely Accessible Method Object Browser API");
  script_summary(english:"Finds /mob directory containing VMware ESX / ESXi Method Object Browser API.");

  script_set_attribute(attribute:"synopsis", value:
"A method object browser API is accessible on the remote VMware ESX / ESXi host.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESX / ESXi host has a Method Object Browser API accessible in the /mob directory on the web 
interfaces. This is disabled by default. If enabled, the MOB allows remote attackers to invoke methods on 
VMware ESX / ESXi objects, including create and destroy. This can allow a remote attacker to interact with the 
hypervisor server. ESXi credentials and permissions are required to use the MOB.");

  # https://pubs.vmware.com/vsphere-50/index.jsp?topic=%2Fcom.vmware.wssdk.pg.doc_50%2FPG_ChB_Using_MOB.20.2.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cd83d552");
  script_set_attribute(attribute:"solution", value:
"Ensure only valid administrators have accounts and privileges on the ESXi host. Use of local accounts should be 
limited only to the most trusted administrators and should be using the built in RBAC capabilities. If the MOB is 
enabled then this will limit the scope of what can be done using the MOB. Note: The MOB is disabled by default on 
ESXi.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
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

res = http_send_recv3(method:'GET', item:"/mob/?moid=ServiceInstance&doPath=content", port:port, username:"root", password:"", exit_on_fail:TRUE);

if ("Managed Object Browser" >< res[2])
{
  report = '\n' +
'  Nessus was able to access the VMware ESX / ESXi Method Object\n' +
'  Browser remote API using the following request:\n' +
'    ' + build_url(port:port, qs:"/mob/?moid=ServiceInstance&doPath=content", username:"root", password:"") + '\n' +
'\n' +
'  The following content object types are accessible on the remote host:\n';
  lines = split(res[2], sep:'<td class="c1">');
  foreach line (lines)
  {
    matches = pregmatch(string:line, pattern:'<td class="c2">(.*)</td>');
    if (isnull(matches)) continue;

    objecttype = matches[1];
    report += "    " + objecttype + '\n';
  }

  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
  exit(0);
}
else audit(AUDIT_WEB_FILES_NOT, "VMware ESX / ESXi Method Object Browser API", port);
