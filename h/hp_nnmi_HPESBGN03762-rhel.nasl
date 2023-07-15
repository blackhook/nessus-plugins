#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101296);
  script_version("1.3");
  script_cvs_date("Date: 2018/07/12 19:01:16");
  
  script_cve_id("CVE-2017-8948");
  script_bugtraq_id(99342);
  script_xref(name:"HP", value:"HPESBGN03762");
  script_xref(name:"HP", value:"emr_na-hpesbgn03762en_us");
  script_xref(name:"IAVA", value:"2017-A-0193");
  
  script_name(english:"HPE Network Node Manager i (NNMi) Multiple Vulnerabilities (HPESBGN03762)");
  script_summary(english:"Checks the version of HPE Network Node Manager i.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Linux host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of HPE Network Node Manager i (NNMi) installed on the
remote Linux host is 10.0x prior to 10.00 Patch 5, 10.1x prior to
10.10 Patch 4, or 10.2x prior to 10.20 Patch 3. It is, therefore,
affected by multiple vulnerabilities that allow an unauthenticated,
remote attacker to execute arbitrary code, bypass security
restrictions, and perform unauthorized actions.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-hpesbgn03762en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?821afdbf");
  script_set_attribute(attribute:"solution", value:
"Upgrade to HPE Network Node Manager i version 10.00 Patch 5 / 10.10
Patch 4 / 10.20 Patch 3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  
  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/07");
  
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:network_node_manager_i");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");

  script_dependencies("hp_nnmi_installed_nix.nasl");
  script_require_keys("installed_sw/HP Network Node Manager i", "Host/RedHat/release", "Host/cpu");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

# Boiler plate RHEL
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "ppc" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

app_name = "HP Network Node Manager i";
install  = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
ver      = install["version"];
path     = install["path"];
port     = 0;

report_ver = ver;
installed_patch = install["Patch"];

if (empty_or_null(installed_patch))
  installed_patch = 0;
else
  report_ver = ver + " with Patch " + installed_patch;

fix_patch = 0;

if (ver =~ "^10\.0[0-9]($|[^0-9])")      fix_patch = 5;
else if (ver =~ "^10\.1[0-9]($|[^0-9])") fix_patch = 4;
else if (ver =~ "^10\.2[0-9]($|[^0-9])") fix_patch = 3;
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, ver, path);

if (installed_patch >= fix_patch)
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, report_ver, path);

report =
  '\n  Path              : ' + path +
  '\n  Installed version : ' + report_ver +
  '\n  Missing patch     : ' + fix_patch +
  '\n';

security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
