#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134563);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/16");

  script_cve_id("CVE-2019-8462");

  script_name(english:"Check Point Security Gateway Denial of Service (sk161812)");
  script_summary(english:"Checks the version of Checkpoint GAIA.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"A denial of service (DoS) vulnerability exists in Checkpoint Security Gateway R80.30 when the Threat Prevention Forensics
feature is enabled. An authenticated, local attacker can exploit this issue by implementing a specific copnfiguration
of enhanced logging, to cause the system to stop responding.");
  # https://supportcenter.checkpoint.com/supportcenter/portal?eventSubmit_doGoviewsolutiondetails=&solutionid=sk161812&src=securityAlerts
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4bb28b91");
  script_set_attribute(attribute:"solution", value:
"See the vendor advisory for workarounds.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-8462");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/13");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:check_point:gaia_os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("check_point_gaia_os_version.nbin");
  script_require_keys("Host/Check_Point/version", "Settings/ParanoidReport");

  exit(0);
}

if (report_paranoia < 2) audit(AUDIT_PARANOID);

version  = get_kb_item('Host/Check_Point/version');
hotfix = get_kb_item('Host/Check_Point/hotfixes');

if (version != 'R80.30' || version == NULL || hotfix == 'sk153152') {
  audit(AUDIT_DEVICE_NOT_VULN, 'The remote device running Gaia Operating System (version ' + version + ')');
}
report =
  '\n  Installed version      : ' + version +
  '\n  Hotfix required        : Hotfix sk153152' +
  '\n  vulnerable version was installed.\n';
security_report_v4(port:0, severity:SECURITY_WARNING, extra:report);
