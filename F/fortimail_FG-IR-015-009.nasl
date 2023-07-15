#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(82996);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2015-3293");
  script_bugtraq_id(71543);

  script_name(english:"Fortinet FortiMail < 5.0.9 / 5.1.6 / 5.2.4 HTTP Debug Information Disclosure");
  script_summary(english:"Checks the version of FortiMail.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of FortiMail that is prior to
5.0.9 / 5.1.6 / 5.2.4. It is, therefore, affected by an information
disclosure vulnerability due to HTTP debug commands improperly dumping
user credentials in the debug logs. This allows a remote,
authenticated attacker to disclose user credentials entered in the
admin WebGUI and webmail login page forms.");
  script_set_attribute(attribute:"see_also", value:"https://fortiguard.com/psirt/FG-IR-15-009");
  script_set_attribute(attribute:"solution", value:
"No fix is currently available at this time (2015/04/21).
      
The vendor plans to release FortiMail 5.0.9 / 5.1.6 / 5.2.4 to address
the vulnerability.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:fortinet:fortimail");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/model", "Host/Fortigate/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "FortiMail";
model    = get_kb_item_or_exit("Host/Fortigate/model");
version  = get_kb_item_or_exit("Host/Fortigate/version");

# Make sure device is FortiMail.
if (!preg(string:model, pattern:"fortimail", icase:TRUE)) audit(AUDIT_HOST_NOT, "a " + app_name + " device");

if (version =~ "^5\.0\.") fix = "5.0.9";
else if (version =~ "^5\.1\.") fix = "5.1.6";
else if (version =~ "^5\.2\.") fix = "5.2.4";
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);

if (
  ver_compare(ver:version, fix:fix, strict:FALSE) == -1 &&
  ver_compare(ver:version, fix:'5.0.3', strict:FALSE) >= 0
)
{
  port = 0;
  if (report_verbosity > 0)
  {
    report =
      '\n  Model             : ' + model +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : Contact the vendor for a fix.' +
      '\n';

    security_warning(extra:report, port:port);
  }
  else security_warning(port:port);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);
