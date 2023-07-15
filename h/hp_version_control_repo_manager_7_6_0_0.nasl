#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96721);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/13");

  script_cve_id(
    "CVE-2016-7052",
    "CVE-2016-8513",
    "CVE-2016-8514",
    "CVE-2016-8515"
  );
  script_bugtraq_id(93171, 94949);
  script_xref(name:"HP", value:"emr_na-c05356363");
  script_xref(name:"IAVB", value:"2017-B-0025");
  script_xref(name:"HP", value:"HPSBMU03684");

  script_name(english:"HP Version Control Repository Manager < 7.6.0 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of HP VCRM.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the HP Version Control
Repository Manager (VCRM) application installed on the remote Windows
host is prior to 7.6.0. It is, therefore, affected by multiple
vulnerabilities :

  - A denial of service vulnerability exists in OpenSSL in
    x509_vfy.c due to improper handling of certificate
    revocation lists (CRLs). An unauthenticated, remote
    attacker can exploit this, via a specially crafted CRL,
    to cause a NULL pointer dereference, resulting in a
    crash of the service. (CVE-2016-7052)

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
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20160926.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to HP Version Control Repository Manager version 7.6.0 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-8515");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:version_control_repository_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("hp_version_control_repo_manager_installed.nbin");
  script_require_keys("installed_sw/HP Version Control Repository Manager");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

appname = "HP Version Control Repository Manager";
install = get_single_install(app_name:appname, exit_if_unknown_ver:TRUE);
version = install['version'];
path = install['path'];

fix = '7.6.0.0';

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

   report =
        '\n  Path              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fix +
        '\n';

  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING, xsrf:TRUE);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, version, path);
