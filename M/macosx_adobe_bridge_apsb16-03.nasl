#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88720);
  script_version("1.10");
  script_cvs_date("Date: 2019/11/20");

  script_cve_id("CVE-2016-0951", "CVE-2016-0952", "CVE-2016-0953");
  script_bugtraq_id(83114);

  script_name(english:"Adobe Bridge CC < 6.2 Multiple Memory Corruption Vulnerabilities (APSB16-03) (Mac OS X)");
  script_summary(english:"Checks the Bridge version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by
multiple memory corruption vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Bridge installed on the remote Mac OS X host is
prior to 6.2. It is, therefore, affected by multiple unspecified
memory corruption issues due to improper validation of user-supplied
input. An unauthenticated, remote attacker can exploit these issues to
execute arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/photoshop/apsb16-03.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Bridge CC version 6.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-0953");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:bridge");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:bridge_cc");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_adobe_bridge_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Adobe Bridge");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");
include("install_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

os = get_kb_item('Host/MacOSX/Version');
if (!os) audit(AUDIT_OS_NOT, 'Mac OS X');

get_kb_item_or_exit("installed_sw/Adobe Bridge");

app = 'Adobe Bridge';

install=get_single_install(app_name:app, exit_if_unknown_ver:TRUE);

product = install['name'];
if ("CC" >!< product)
  exit(0, "Only Adobe Bridge CC is affected.");

path    = install['path'];
version = install['version'];

# version < 6.1.1 Vuln
fix = '6.2';

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  if (report_verbosity > 0)
  {
    report = '\n  Product           : ' + product +
             '\n  Path              : ' + path +
             '\n  Installed version : ' + version +
             '\n  Fixed version     : ' + fix;

    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
audit(AUDIT_INST_VER_NOT_VULN, app + " CC", version);
