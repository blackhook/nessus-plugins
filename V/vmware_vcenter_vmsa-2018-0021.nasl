#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(112207);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/04");

  script_cve_id("CVE-2018-3620");
  script_bugtraq_id(105080);
  script_xref(name:"VMSA", value:"2018-0021");

  script_name(english:"VMware vCenter Server Appliance 6.0 / 6.5 / 6.7 Information Disclosure vulnerability (VMSA-2018-0021)");
  script_summary(english:"Checks version of VMware vCenter Server Appliance");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a virtualization appliance installed that is
affected an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vCenter Server Appliance installed on the
remote host is 6.0, 6.5 or 6.7 and is, therefore, potentially
affected by an information disclosure vulnerability. (CVE-2018-3620)");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2018-0021.html");
  script_set_attribute(attribute:"see_also", value:"https://kb.vmware.com/s/article/55636");
  script_set_attribute(attribute:"see_also", value:"https://kb.vmware.com/s/article/52312");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware vCenter Server Appliance 6.5 Update 2d / 6.7 Update 1 or later,
or implement operating system mitigations described in VMware kb article.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-3620");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vcenter_server_appliance");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/VMware vCenter Server Appliance/Version", "Host/VMware vCenter Server Appliance/Build");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = 'VMware vCenter Server Appliance';
version = get_kb_item_or_exit("Host/VMware vCenter Server Appliance/Version");
build = get_kb_item_or_exit("Host/VMware vCenter Server Appliance/Build");

fixversion = NULL;

if ( version =~ "^6\.7" && int(build) < 10244745 ) fixversion = '6.7.0 build-10244745';
else if ( version =~ "^6\.5" && int(build) < 10964411 ) fixversion = '6.5.0 build-10964411';
else if ( version =~ "^6\.0" ) fixversion = 'Apply Workaround';
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version, build);

report = report_items_str(
  report_items:make_array(
  'Installed version', version + ' build-' + build,
  'Fixed version', fixversion
  ),
  ordered_fields:make_list('Installed version', 'Fixed version')
);

security_report_v4(port:0, severity:SECURITY_WARNING, extra:report);
