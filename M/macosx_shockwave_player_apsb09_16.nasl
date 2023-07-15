#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(80170);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2009-3244",
    "CVE-2009-3463",
    "CVE-2009-3464",
    "CVE-2009-3465",
    "CVE-2009-3466"
  );
  script_bugtraq_id(36905);

  script_name(english:"Adobe Shockwave Player <= 11.5.1.601 Multiple Vulnerabilities (APSB09-16) (Mac OS X)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser plugin that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host contains a version of Adobe Shockwave Player
that is 11.5.1.601 or earlier. It is, therefore, affected by multiple
vulnerabilities :

  - An invalid index vulnerability allows code execution.
    (CVE-2009-3463)

  - Invalid pointer vulnerabilities that allow code
    execution. (CVE-2009-3464, CVE-2009-3465)

  - An invalid string length vulnerability allows code
    execution. (CVE-2009-3466)

  - A boundary condition issue allows a denial of service.
    (CVE-2009-3244)");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb09-16.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Shockwave version 11.5.2.602 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2009-3466");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(94, 119, 399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/11/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:shockwave_player");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("shockwave_player_detect_macosx.nbin");
  script_require_keys("installed_sw/Shockwave Player", "Host/MacOSX/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

app = 'Shockwave Player';

get_install_count(app_name:app, exit_if_zero:TRUE);

install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);

ver = install['version'];
path = install['path'];

if (ver_compare(ver:ver, fix:'11.5.1.601', strict:FALSE) <= 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + ver +
      '\n  Fixed versions    : 11.5.2.602' +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(port:0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, ver, path);
