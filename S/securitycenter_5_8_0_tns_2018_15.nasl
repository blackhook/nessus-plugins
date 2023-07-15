#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(119149);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/09");

  script_cve_id(
    "CVE-2013-2153",
    "CVE-2013-2154",
    "CVE-2013-2155",
    "CVE-2013-2156",
    "CVE-2013-2210",
    "CVE-2013-4517",
    "CVE-2014-0107"
  );
  script_bugtraq_id(
    60592,
    60594,
    60595,
    60599,
    60817,
    64437,
    66397
  );

  script_name(english:"Tenable SecurityCenter < 5.8.0 Multiple Vulnerabilities (TNS-2018-15)");
  script_summary(english:"Checks the SecurityCenter version.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable SecurityCenter
application installed on the remote host is 5.7.1 or earlier. It is,
therefore, affected by multiple vulnerabilities.

Note that Nessus has not tested for these issues nor the stand-alone
patch but has instead relied only on the application's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2018-15");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tenable SecurityCenter version 5.8.0 or later or apply
SecurityCenter Patch 201811.1.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0107");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/27");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:securitycenter");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("securitycenter_installed.nbin", "securitycenter_detect.nbin");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Host/SecurityCenter/Version", "installed_sw/SecurityCenter");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

version = get_kb_item("Host/SecurityCenter/Version");
port = 0;
if(empty_or_null(version))
{
  port = 443;
  install = get_single_install(app_name:"SecurityCenter", combined:TRUE, exit_if_unknown_ver:TRUE);
  version = install["version"];
}
fix = "5.8.0";

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  items = make_array(
    "Installed version", version,
    "Fixed version", fix
  );
  order = make_list("Installed version", "Fixed version");
  report = report_items_str(report_items:items, ordered_fields:order);

  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
}
else
  audit(AUDIT_INST_VER_NOT_VULN, 'SecurityCenter', version);
