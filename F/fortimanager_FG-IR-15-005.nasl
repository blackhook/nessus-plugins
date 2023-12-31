#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(86471);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2015-3620");
  script_bugtraq_id(74646);

  script_name(english:"Fortinet FortiManager FortiOS 5.0.x >= 5.0.3 and < 5.0.11 Dataset Reports XSS");
  script_summary(english:"Checks the FortiOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Fortinet FortiManager FortiOS version running on the remote host
is 5.x greater than or equal to 5.0.3 and prior to 5.0.11. It is,
therefore, affected by a cross-site scripting vulnerability in the
advanced dataset reports page due to a failure to properly sanitize
user-supplied input to the 'sql-query' GET parameter before returning
it to users. An unauthenticated, remote attacker can exploit this, via
a crafted request, to execute arbitrary script code or HTML in the
user's browser session. Note that this issue applies when the
FortiAnalyzer feature is enabled.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2015/May/29");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiOS version 5.0.11.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/02/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortimanager_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/model", "Host/Fortigate/version", "Host/Fortigate/build");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "FortiManager";
model = get_kb_item_or_exit("Host/Fortigate/model");
version = get_kb_item_or_exit("Host/Fortigate/version");
build = get_kb_item_or_exit("Host/Fortigate/build");
vuln = FALSE;

# Make sure device is FortiManager.
if (!preg(string:model, pattern:"fortimanager", icase:TRUE)) audit(AUDIT_HOST_NOT, "a " + app_name + " device");

if (version =~ "^5\.")
{
  fix = "5.0.11";
  min_ver_vuln = "5.0.3";

  # http://docs.fortinet.com/uploaded/files/2456/fortimanager-v5.0.11-release-notes.pdf
  fix_build = 377;
  # http://docs.fortinet.com/uploaded/files/1136/FortiManager-v5.0-Patch-Release-3-Release-Notes.pdf
  min_build_vuln = 200;
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);

# If build number is available, this is the safest comparison.
# Otherwise compare version numbers.
if (build !~ "Unknown")
{
  if (int(build) < fix_build && int(build) >= min_build_vuln) vuln = TRUE;
}
else if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1 &&
         ver_compare(ver:version, fix:min_ver_vuln, strict:FALSE) >= 0)
  vuln = TRUE;

if (vuln)
{
  port = 0;
  set_kb_item(name:"www/"+port+"/XSS", value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  Model             : ' + model +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';

    security_warning(extra:report, port:port);
  }
  else security_warning(port:port);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);
