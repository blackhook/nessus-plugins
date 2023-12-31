#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85741);
  script_version("1.7");
  script_cvs_date("Date: 2019/01/02 11:18:37");


  script_name(english:"Fortinet FortiOS 5.0.x < 5.0.2 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of FortiOS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Fortinet FortiOS 5.0.x prior
to 5.0.2. It is, therefore, affected by the following
vulnerabilities :

  - A security bypass vulnerability exists due to a flaw 
    when using SMTP. An unauthenticated, remote attacker can
    exploit this to bypass the DLP full content archive.

  - An unspecified flaw exists in the SSL renegotiation
    functionality that an unauthenticated, remote attacker
    can exploit to cause a denial of service condition.
");
  # https://kb.fortinet.com/kb/microsites/search.do?cmd=displayKC&docType=kc&externalId=FortiOS-v50-Patch-Release-2-Release-Notespdf
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?b8916821");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiOS 5.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/model", "Host/Fortigate/version", "Host/Fortigate/build");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "FortiOS";
model    = get_kb_item_or_exit("Host/Fortigate/model");
version  = get_kb_item_or_exit("Host/Fortigate/version");
build    = get_kb_item_or_exit("Host/Fortigate/build");
vuln     = FALSE;

# Make sure device is FortiGate
if (!preg(string:model, pattern:"fortigate", icase:TRUE)) audit(AUDIT_OS_NOT, app_name);

if (version =~ "^5\.")
{
  fix = "5.0.2";
  fix_build = 179;
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);

# If build number is available, this is the safest comparison.
# Otherwise compare version numbers.
if (build !~ "Unknown")
{
  if (int(build) < fix_build) vuln = TRUE;
  report_build = build;
}
else if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1) vuln = TRUE;

if (vuln)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Model             : ' + model +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 5.0.2';
    if (!empty_or_null(report_build))
      report +=
        '\n  Installed build   : ' + report_build +
        '\n  Fixed build       : ' + fix_build;

    report += '\n';
    security_hole(extra:report, port:0);
  }
  else security_hole(port:0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);
