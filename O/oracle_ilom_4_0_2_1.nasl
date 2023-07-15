#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(107266);
  script_version("1.3");
  script_cvs_date("Date: 2018/07/16 14:09:12");

  script_cve_id(
    "CVE-2016-0704",
    "CVE-2018-2566",
    "CVE-2018-2568"
  );
  script_bugtraq_id(
    83764,
    102603,
    102606
  );

  script_name(english:"Oracle Integrated Lights Out Manager (ILOM) < 4.0.2.1 Multiple Vulnerabilities (uncredentialed check)");
  script_summary(english:"Checks DCNM version number");

  script_set_attribute(attribute:"synopsis", value:
"A network management system installed on the remote host is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of Oracle
Integrated Lights Out Manager (ILOM) is affected by multiple vulnerabilities
as described in the advisory.");
  # http://www.oracle.com/technetwork/security-advisory/cpujan2018-3236628.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ae82f1b1");
  script_set_attribute(attribute:"solution", value:"Upgrade to Oracle Integrated Lights Out Manager (ILOM) 4.0.2.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sun:embedded_lights_out_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:integrated_lights_out_manager_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018 Tenable Network Security, Inc.");

  script_dependencies("oracle_ilom_web_detect.nasl");
  script_require_keys("installed_sw/ilom", "Settings/ParanoidReport");

  exit(0);
}

include("http.inc");
include("vcf.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

get_install_count(app_name:"ilom", exit_if_zero:TRUE);

port = get_http_port(default:443);
app = "ilom";

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);
vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
      {"min_version" : "3.0.0", "fixed_version" : "4.0.2.1"  }

];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

