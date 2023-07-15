#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(135593);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/17");

  script_cve_id("CVE-2020-3767", "CVE-2020-3768", "CVE-2020-3796");
  script_xref(name:"IAVA", value:"2020-A-0164-S");

  script_name(english:"Adobe ColdFusion 2016.x < 2016u15 / 2018.x < 2018u9 Multiple Vulnerabilities (APSB20-18)");

  script_set_attribute(attribute:"synopsis", value:
"A web-based application running on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe ColdFusion installed on the remote Windows host is prior to 2016.x update 15 or 2018.x prior to
update 9. It is, therefore, affected by the following vulnerabilities as referenced in the APSB20-18 advisory:

  - An application-level denial of service (DoS) vulnerability due to insufficient input validation.
    (CVE-2020-3767)

  - A privilege escalation vulnerability related to DLL search-order hijacking. (CVE-2020-3768)

  - A system file structure disclosure vulnerability due to improper access control. (CVE-2020-3796)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/coldfusion/apsb20-18.html");
  script_set_attribute(attribute:"solution", value:
"Update to Adobe ColdFusion version 2016 update 15 / 2018 update 9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3768");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:coldfusion");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("coldfusion_win_local_detect.nasl");
  script_require_keys("SMB/coldfusion/instance");
  script_require_ports(139, 445);

  exit(0);
}

include('coldfusion_win.inc');
include('misc_func.inc');

instances = get_coldfusion_instances(); # this exits if it fails

# Check the hotfixes and cumulative hotfixes
# installed for each instance of ColdFusion.
instance_info = make_list();

foreach name (keys(instances))
{
  info = NULL;
  ver = instances[name];

  if (ver == '2018.0.0')
  {
    info = check_jar_chf(name, 9);
  }
  else if (ver == '2016.0.0')
  {
    info = check_jar_chf(name, 15);
  }
  if (!isnull(info))
    instance_info = make_list(instance_info, info);
}

if (max_index(instance_info) == 0)
  audit(AUDIT_INST_VER_NOT_VULN, 'Adobe ColdFusion');

port = get_kb_item('SMB/transport');
if (!port)
  port = 445;

report =
  '\n' + 'Nessus detected the following unpatched instances :' +
  '\n' + join(instance_info, sep:'\n') +
  '\n';

security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
