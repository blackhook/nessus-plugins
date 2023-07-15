#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(117480);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/30");

  script_cve_id(
    "CVE-2018-15965",
    "CVE-2018-15957",
    "CVE-2018-15958",
    "CVE-2018-15959",
    "CVE-2018-15964",
    "CVE-2018-15963",
    "CVE-2018-15962",
    "CVE-2018-15961",
    "CVE-2018-15960"
    );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"Adobe ColdFusion 11.x < 11u15 / 2016.x < 2016u7 / 2018.x < 2018u1 Multiple Vulnerabilities (APSB18-33)");
  script_summary(english:"Checks the hotfix files.");

  script_set_attribute(attribute:"synopsis", value:
"A web-based application running on the remote host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe ColdFusion running on the remote Windows host is
11.x prior to update 15, 2016.x prior to update 7 or 2018.x prior to
update 1. It is, therefore, affected by multiple vulnerabilities."
  );
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/coldfusion/apsb18-33.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe ColdFusion version 11 update 15 / 2016 update 7 /
2018 update 1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15965");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Adobe ColdFusion File Upload");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe ColdFusion CKEditor unrestricted file upload');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:coldfusion");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("coldfusion_win_local_detect.nasl");
  script_require_keys("SMB/coldfusion/instance");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("coldfusion_win.inc");
include("global_settings.inc");
include("misc_func.inc");

versions = make_list('11.0.0', '2016.0.0', '2018.0.0');
instances = get_coldfusion_instances(versions); # this exits if it fails

# Check the hotfixes and cumulative hotfixes
# installed for each instance of ColdFusion.
info = NULL;
instance_info = make_list();

foreach name (keys(instances))
{
  info = NULL;
  ver = instances[name];

  if (ver == "11.0.0")
  {
    info = check_jar_chf(name, 15);
  }

  else if (ver == "2016.0.0")
  {
    info = check_jar_chf(name, 7);
  }
  else if (ver == "2018.0.0")
  {
    info = check_jar_chf(name, 1);
  }
  if (!isnull(info))
    instance_info = make_list(instance_info, info);
}

if (max_index(instance_info) == 0)
  exit(0, "No vulnerable instances of Adobe ColdFusion were detected.");

port = get_kb_item("SMB/transport");
if (!port)
  port = 445;

report =
  '\n' + 'Nessus detected the following unpatched instances :' +
  '\n' + join(instance_info, sep:'\n') +
  '\n';

security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
exit(0);
