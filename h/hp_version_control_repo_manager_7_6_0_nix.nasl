#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96722);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/25");

  script_cve_id("CVE-2016-8513", "CVE-2016-8514", "CVE-2016-8515");
  script_bugtraq_id(94949);
  script_xref(name:"HP", value:"emr_na-c05356363");
  script_xref(name:"IAVB", value:"2017-B-0025");
  script_xref(name:"HP", value:"HPSBMU03684");

  script_name(english:"HP Version Control Repository Manager for Linux < 7.6.0 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of HP VCRM.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Linux host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the HP Version Control
Repository Manager (VCRM) application installed on the remote Linux
host is prior to 7.6.0. It is, therefore, affected by multiple
vulnerabilities :

  - A cross-site request forgery (XSRF) vulnerability exists
    in VCRM due to HTTP requests not requiring multiple
    steps, explicit confirmation, or a unique token when
    performing certain sensitive actions. An
    unauthenticated, remote attacker can exploit this, by
    convincing a user into following a specially crafted
    link, to perform unspecified actions. (CVE-2016-8513)

  - An unspecified flaw exists in VCRM that allows an
    authenticated, remote attacker to disclose potentially
    sensitive information. (CVE-2016-8514)

  - An unspecified flaw exists in VCRM that allows an
    authenticated, remote attacker to upload arbitrary files.
    (CVE-2016-8515)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://support.hpe.com/hpsc/doc/public/display?docId=emr_na-c05356363
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b6730ba8");
  script_set_attribute(attribute:"solution", value:
"Upgrade to HP Version Control Repository Manager version 7.6.0 or
later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-8515");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/12/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:version_control_repository_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("hp_version_control_repo_manager_installed_nix.nasl");
  script_require_keys("installed_sw/HP Version Control Repository Manager for Linux");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app_name = "HP Version Control Repository Manager for Linux";
install  = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
ver      = install['version'];
path     = install['path'];
port     = 0;

fix = '7.6.0';

if (ver_compare(ver:ver, fix:fix, strict:FALSE) < 0)
{
  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING, xsrf:TRUE);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, ver, path);
