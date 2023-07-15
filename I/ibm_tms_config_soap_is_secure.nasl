#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101168);
  script_version("1.3");
  script_cvs_date("Date: 2018/07/12 19:01:17");

  script_cve_id("CVE-2016-6083");
  script_bugtraq_id(99259);
  script_xref(name:"IAVA", value:"2017-A-0187");

  script_name(english:"IBM Tivoli Monitoring SOAP Interface Insecure Configuration Remote SOAP Query Information Disclosure");
  script_summary(english:"Checks for configuration option in ms.ini.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the Windows host is affected by an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"IBM Tivoli Monitoring, a network asset monitoring platform, is
installed on the remote Windows host and is using an insecure
configuration. It is, therefore, affected by an information disclosure
vulnerability in the SOAP interface due to an insecure default
configuration. An unauthenticated, remote attacker can exploit this to
disclose SOAP queries that may contain sensitive information.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg22000909");
  script_set_attribute(attribute:"solution", value:
"Apply the interim fix or workaround per the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/30");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_monitoring");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_ports(139, 445);
  script_require_keys("SMB/Registry/Enumerated", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

# Exit unless we're paranoid because we don't have a good way to validate
# that the Security: Validate User option is configured
if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = kb_smb_transport();
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

app = 'IBM Tivoli Monitoring';
configured_to_be_secure = FALSE;

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key  = "SOFTWARE\Candle\OMEGAMON\Directory";
path = get_registry_value(handle:hklm, item:key);
RegCloseKey(handle:hklm);

if (isnull(path))
{
  close_registry();
  audit(AUDIT_NOT_INST, app);
}
close_registry(close:FALSE);

config_file = hotfix_append_path(path:path, value:"\cms\KBBENV");
share = hotfix_path2share(path:path);

file = hotfix_get_file_contents(config_file);
contents = file["data"];

hotfix_handle_error(
  error_code   : file["error"],
  file         : config_file,
  appname      : app,
  exit_on_fail : TRUE
);

if (!contents) audit(AUDIT_FN_FAIL, 'hotfix_get_file_contents', 'no file contents');

# Looking for an uncommented 'SOAP_IS_SECURE=YES'
lines = pgrep(string:contents, pattern:"SOAP_IS_SECURE");

foreach line (split(lines))
{
  pieces = split(line, sep:'=', keep:FALSE);

  conf_opt = strip(pieces[0]);
  conf_val = strip(pieces[1]);

  if (
    conf_opt == 'SOAP_IS_SECURE' &&
    conf_val =~ "^[Yy][Ee][Ss]$"
  )
    configured_to_be_secure = TRUE;
}

if (!configured_to_be_secure)
{
  port = kb_smb_transport();
  if (!port) port = 445;

  security_report_v4(
    port:port,
    severity:SECURITY_WARNING,
    extra: '\n' +
           '\n  Configuration file, "' +
           config_file +
           '" does not contain uncommented "SOAP_IS_SECURE=YES"' +
           '\n'
  );
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, "unknown", path);
