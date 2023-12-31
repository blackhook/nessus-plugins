#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(84920);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");


  script_name(english:"Fortinet FortiAnalyzer 5.0.x < 5.0.8 Alert Email Plaintext Password Disclosure");
  script_summary(english:"Checks the version of FortiAnalyzer.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is potentially affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Fortinet FortiAnalyzer running on the remote host is
5.0.x prior to 5.0.8. It is, therefore, potentially affected by an
information disclosure vulnerability due to passwords being printed in
plaintext by the 'Alert email debug' feature. This allows a local
attacker to view the passwords in the log when the 'Alert email debug'
feature is enabled.

Note that Nessus has not tested for this issue or the host
configuration but has instead relied only on the application's
self-reported version number.");
  # https://kb.fortinet.com/kb/microsites/search.do?cmd=displayKC&docType=kc&externalId=fortianalyzer-v508-release-notespdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1e087200");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiAnalyzer 5.0.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/22");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortianalyzer_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2021 Tenable Network Security, Inc.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/model", "Host/Fortigate/version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app_name = "FortiAnalyzer";
model = get_kb_item_or_exit("Host/Fortigate/model");
version = get_kb_item_or_exit("Host/Fortigate/version");

# Make sure device is FortiAnalyzer.
if (!preg(string:model, pattern:"fortianalyzer", icase:TRUE)) audit(AUDIT_HOST_NOT, "a " + app_name + " device");

if (version !~ "^5\.") audit(AUDIT_INST_VER_NOT_VULN, app_name, version);

fix = "5.0.8";

if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  port = 0;
  if (report_verbosity > 0)
  {
    report =
      '\n  Model             : ' + model +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';

    security_note(extra:report, port:port);
  }
  else security_note(port:port);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);
