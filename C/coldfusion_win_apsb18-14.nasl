#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(109017);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2018-4938",
    "CVE-2018-4939",
    "CVE-2018-4940",
    "CVE-2018-4941",
    "CVE-2018-4942"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2020-0129");

  script_name(english:"Adobe ColdFusion 11.x < 11u14 / 2016.x < 2016u6 Multiple Vulnerabilities (APSB18-14)");

  script_set_attribute(attribute:"synopsis", value:
"A web-based application running on the remote host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe ColdFusion running on the remote Windows host is
11.x prior to update 14 or 2016.x prior to update 6. It is, therefore,
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/coldfusion/apsb18-14.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe ColdFusion version 11 update 14 / 2016 update 6 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-4939");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:coldfusion");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("coldfusion_win_local_detect.nasl");
  script_require_keys("SMB/coldfusion/instance");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("coldfusion_win.inc");
include("global_settings.inc");
include("misc_func.inc");

versions = make_list('11.0.0', '2016.0.0');
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
    info = check_jar_chf(name, 14);
  }

 else if (ver == "2016.0.0")
  {
    info = check_jar_chf(name, 6);
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

security_report_v4(port:port, extra:report, severity:SECURITY_HOLE, xss:TRUE);
exit(0);
