#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134890);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/26");

  script_cve_id("CVE-2019-8461");

  script_name(english:"Check Point Local Privilege Escalation");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Checkpoint Endpoint Security Initial Client. that is vulnerable to a local
privilege escalation vulnerability. The vulnerability exists because vulnerable versions attempt to load a DLL
that is placed in any PATH location on a clean install. An attacker could leverage this by creating a specially
crafted DLL and placing it in any PATH location, when the victim installs Check Point Endpoint Security Initial
Client, the DLL will be executed as that user. (CVE-2019-8461)");
  # https://supportcenter.checkpoint.com/supportcenter/portal?eventSubmit_doGoviewsolutiondetails=&solutionid=sk161792&src=securityAlerts
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bc8c6396");
  script_set_attribute(attribute:"solution", value:
"See the vendor advisory for workarounds.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-8461");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/25");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:checkpoint:remote_access_clients");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("checkpoint_endpoint_rac_installed.nasl");
  script_require_keys("SMB/Check Point Remote Access Client/98.6.1008.0/VerUI", "Settings/ParanoidReport");

  exit(0);
}

include('global_settings.inc');
include('misc_func.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app_name = 'Endpoint Security Initial Client';
version  = get_kb_item('SMB/Check Point Remote Access Client/98.6.1008.0/VerUI');

# Remove E character so we can compare if version is less than or greater than vuln version
parsed_version = pregmatch(pattern:'(^E)([0-9]+.[0-9]+)',string:version);

if (parsed_version[2] >= '81.30' || parsed_version == NULL)
{
  audit(AUDIT_DEVICE_NOT_VULN, 'The remote device running ' + app_name + ' (version ' + version + ')');
}
else
{
  report =
    '\n  Installed version      : ' + version +
    '\n  Hotfix required        : Hotfix sk160812' +
    '\n  vulnerable version was installed.\n';

  security_report_v4(port:0, severity:SECURITY_WARNING, extra:report);
}
