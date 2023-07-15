#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(108689);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2018-1141");

  script_name(english:"Tenable Nessus < 7.0.3 Sub-directory Missing Secure Permission Local Privilege Escalation (TNS-2018-01)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote host is affected by a local
privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable Nessus application
running on the remote host is prior to 7.0.3. It is, therefore,
affected by a local privilege escalation vulnerability due to the
program failing to enforce secure permissions for sub-directories when
a directory is installed outside of the default location.

This plugin is only checking the remote version and has not checked
for installation location.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2018-01");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tenable Nessus version 7.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1141");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:nessus");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nessus_detect.nasl");
  script_require_keys("installed_sw/nessus", "Settings/ParanoidReport");
  script_require_ports("Services/www", 8834);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("install_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app = "nessus";
get_install_count(app_name:app, exit_if_zero:TRUE);
port = get_http_port(default:8834);

install = get_single_install(app_name:app, port:port, exit_if_unknown_ver:TRUE);

version = install['version'];

fix = '7.0.3';

# Affected versions:
# < 7.0.3
if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  order = make_list('Installed version', 'Fixed version');
  report = make_array(
    order[0], version,
    order[1], fix
  );
  report = report_items_str(report_items:report, ordered_fields:order);

  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Nessus", port, version);
