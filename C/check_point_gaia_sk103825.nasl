#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(105085);
  script_version("1.3");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2014-9293", "CVE-2014-9294", "CVE-2014-9295");
  script_bugtraq_id(71757, 71761, 71762);
  script_xref(name:"CERT", value:"852879");

  script_name(english:"Check Point Gaia Operating System < R77.20 Multiple NTP Client Vulnerabilities (sk103825)");
  script_summary(english:"Checks the version of Gaia OS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is potentially affected by multiple NTP client vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Gaia Operating System
that is prior to R77.20 and thus, is potentially affected by
multiple NTP client vulnerabilities.

Note that NTP client is disabled by default.

Further note that if the vendor's suggested mitigations are
in place, this can be considered a false positive.");
  # https://supportcenter.checkpoint.com/supportcenter/portal?eventSubmit_doGoviewsolutiondetails=&solutionid=sk103825&src=securityAlerts
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?41e4c4c0");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version R77.20, apply the vendor supplied
mitigations or contact the vendor for further
information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/07");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:check_point:gaia_os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("check_point_gaia_os_version.nbin");
  script_require_keys("Host/Check_Point/version", "Host/Check_Point/model", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "Gaia Operating System";
version  = get_kb_item_or_exit("Host/Check_Point/version");
model    = get_kb_item_or_exit("Host/Check_Point/model");
vuln     = FALSE;

if (model !~ "^Check Point [46]1000")
  audit(AUDIT_HOST_NOT, "model 41000 / 61000");

matches = pregmatch(pattern:"^R(\d+((\.\d+)+)?)", string:version);
if (!matches)
  audit(AUDIT_VER_FORMAT, version);

if (ver_compare(ver:matches[1], fix:"77.20", strict:FALSE) < 0)
  vuln = TRUE;

if(vuln && report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN, app_name, version);

if(vuln)
{
  report =
    '\n  Installed version      : ' + version +
    '\n  Hotfix required        : See Solution.' +
    '\n';
  security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_DEVICE_NOT_VULN, "The remote device running " + app_name + " (version " + version + ")");
