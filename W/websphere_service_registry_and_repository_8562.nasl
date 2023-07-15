#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134308);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/10");

  script_cve_id("CVE-2019-4537");
  script_xref(name:"IAVB", value:"2020-B-0012");

  script_name(english:"IBM WebSphere Service Registry and Repository 8.5 < 8.5.6.2 Information Disclosure Vulnerability");
  script_summary(english:"Checks the version of WebSphere Service Registry and Repository.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web application installed that is affected by
an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IBM WebSphere Service Registry and Repository (WSRR) is
version 8.5 prior to 8.5.6.2. It is therefore, affected by an information
disclosure vulnerability");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/3436359");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM WebSphere Service Registry and Repository Fix Pack
8.5.6.2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-4537");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_service_registry_and_repository");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("websphere_service_registry_repository_installed.nasl");
  script_require_keys("installed_sw/IBM WebSphere Service Registry and Repository");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = 'IBM WebSphere Service Registry and Repository';
fix = '8.5.6.2';

install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
path = install['path'];
version = install['version'];

if (version =~ '^8\\.5\\.' && ver_compare(ver:version, fix:fix) < 0)
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;
    
  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix + '\n';

  security_report_v4(
    port: port,
    severity: SECURITY_WARNING,
    extra: report
    );
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);