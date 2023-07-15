#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(111795);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/26");

  script_cve_id("CVE-2018-1154", "CVE-2018-1155");
  script_xref(name:"IAVB", value:"2018-B-0102-S");

  script_name(english:"Tenable SecurityCenter < 5.7.0 Multiple Vulnerabilites (TNS-2018-11)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by 
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable SecurityCenter
application installed on the remote host is affected by multiple
vulnerabilities:

  - In SecurityCenter versions prior to 5.7.0, a username
    enumeration issue could allow an unauthenticated
    attacker to automate the discovery of username aliases
    via brute force, ultimately facilitating unauthorized
    access. Server response output has been unified to
    correct this issue. (CVE-2018-1154)

  - In SecurityCenter versions prior to 5.7.0, a cross-site
    scripting (XSS) issue could allow an authenticated
    attacker to inject JavaScript code into an image
    filename parameter within the Reports feature area.
    Properly updated input validation techniques have been
    implemented to correct this issue. (CVE-2018-1155)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2018-11");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch referenced in the vendor advisory or 
upgrade to Tenable SecurityCenter version 5.7.0 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1155");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/16");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:securitycenter");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("securitycenter_installed.nbin", "securitycenter_detect.nbin");
  script_require_ports("Host/SecurityCenter/Version", "installed_sw/SecurityCenter");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

version = get_kb_item("Host/SecurityCenter/Version");
port = 0;
if(empty_or_null(version))
{
  port = 443;
  install = get_single_install(app_name:"SecurityCenter", combined:TRUE, exit_if_unknown_ver:TRUE);
  version = install["version"];
}
fix = "5.7.0";

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  items = make_array(
    "Installed version", version,
    "Fixed version", fix
  );
  order = make_list("Installed version", "Fixed version");
  report = report_items_str(report_items:items, ordered_fields:order);

  security_report_v4(severity:SECURITY_NOTE, port:port, extra:report);
}
else
  audit(AUDIT_INST_VER_NOT_VULN, 'SecurityCenter', version);
