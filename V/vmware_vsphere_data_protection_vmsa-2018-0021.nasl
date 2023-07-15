#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(112208);
  script_version("1.2");
  script_cvs_date("Date: 2019/11/04");

  script_cve_id("CVE-2018-3620");
  script_bugtraq_id(105080);
  script_xref(name:"VMSA", value:"2018-0021");

  script_name(english:"VMware vSphere Data Protection 6.x Information Disclosure Vulnerability (VMSA-2018-0021");
  script_summary(english:"Checks the version of VMware vSphere Data Protection.");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization appliance installed on the remote host is affected
by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vSphere Data Protection installed on the
remote host is 6.x. It is, therefore, affected by an information
disclosure vulnerability.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2018-0021.html");
  script_set_attribute(attribute:"solution", value:
"Implement operating system mitigations described in VMware 
kb article.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-3620");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vsphere_data_protection");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/vSphere Data Protection/Version");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "vSphere Data Protection";

version = get_kb_item_or_exit("Host/vSphere Data Protection/Version");

if (version =~ "^[6]$")
  audit(AUDIT_VER_NOT_GRANULAR, app_name, version);

if (version =~ "^6\.[0-9]")
{
  report = '\n  Installed version : ' + version + '\n';
  security_report_v4(port:0, extra:report, severity:SECURITY_WARNING);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);
