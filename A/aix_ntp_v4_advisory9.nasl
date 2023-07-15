#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102131);
  script_version("3.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/21");

  script_cve_id(
    "CVE-2017-6458",
    "CVE-2017-6462",
    "CVE-2017-6464"
  );
  script_bugtraq_id(
    97045,
    97050,
    97051
  );
  script_xref(name:"CERT", value:"325339");

  script_name(english:"AIX NTP v4 Advisory : ntp_advisory9.asc (IV96311) (IV96312)");
  script_summary(english:"Checks the version of the ntp packages for appropriate iFixes.");

  script_set_attribute(attribute:"synopsis", value:
"The remote AIX host has a version of NTP installed that is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of NTP installed on the remote AIX host is affected by
the following vulnerabilities :

  - Multiple stack-based buffer overflow conditions exist in
    various wrappers around the ctl_putdata() function
    within file ntpd/ntp_control.c due to improper
    validation of certain input from the ntp.conf file.
    An unauthenticated, remote attacker can exploit these,
    by convincing a user into deploying a specially
    crafted ntp.conf file, to cause a denial of service
    condition or possibly the execution of arbitrary code.
    (CVE-2017-6458)

  - A stack-based buffer overflow condition exists in the
    datum_pts_receive() function within file
    ntpd/refclock_datum.c when handling handling packets
    from the '/dev/datum' device due to improper validation
    of certain input. A local attacker can exploit this to
    cause a denial of service condition or the execution of
    arbitrary code. (CVE-2017-6462)

  - A denial of service vulnerability exists when handling
    configuration directives. An authenticated, remote
    attacker can exploit this, via a malformed 'mode'
    configuration directive, to crash the ntpd daemon.
    (CVE-2017-6464)");
  script_set_attribute(attribute:"see_also", value:"https://aix.software.ibm.com/aix/efixes/security/ntp_advisory9.asc");
  script_set_attribute(attribute:"solution", value:
"A fix is available and can be downloaded from the IBM AIX website.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ntp:ntp");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"AIX Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2023 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/AIX/lslpp", "Host/local_checks_enabled", "Host/AIX/version");

  exit(0);
}

include("aix.inc");
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
oslevel = get_kb_item("Host/AIX/version");
if (isnull(oslevel)) audit(AUDIT_UNKNOWN_APP_VER, "AIX");
oslevel = oslevel - "AIX-";

if ( ! get_kb_item("Host/AIX/lslpp") ) audit(AUDIT_PACKAGE_LIST_MISSING);

if ( get_kb_item("Host/AIX/emgr_failure" ) ) exit(0, "This AIX package check is disabled because : "+get_kb_item("Host/AIX/emgr_failure") );

flag = 0;

aix_ntp_vulns = {
  "6.1": {
    "minfilesetver":"6.1.6.0",
    "maxfilesetver":"6.1.6.7",
    "patch":"(IV96311m5a)"
  },
  "7.1": {
    "minfilesetver":"7.1.0.0",
    "maxfilesetver":"7.1.0.7",
    "patch":"(IV96312m5a)"
  },
  "7.2": {
    "minfilesetver":"7.1.0.0",
    "maxfilesetver":"7.1.0.7",
    "patch":"(IV96312m5a)"
  }
};

version_report = "AIX " + oslevel;
if ( empty_or_null(aix_ntp_vulns[oslevel]) ) {
  os_options = join( sort( keys(aix_ntp_vulns) ), sep:' / ' );
  audit(AUDIT_OS_NOT, os_options, version_report);
}

foreach oslevel ( keys(aix_ntp_vulns) ) {
  package_info = aix_ntp_vulns[oslevel];
  minfilesetver = package_info["minfilesetver"];
  maxfilesetver = package_info["maxfilesetver"];
  patch =         package_info["patch"];
  if (aix_check_ifix(release:oslevel, patch:patch, package:"ntp.rte", minfilesetver:minfilesetver, maxfilesetver:maxfilesetver) < 0) flag++;
}

if (flag)
{
  aix_report_extra = ereg_replace(string:aix_report_get(), pattern:"[()]", replace:"");
  aix_report_extra = ereg_replace(string:aix_report_extra, pattern:"[|]", replace:" or ");
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : aix_report_extra
  );
}
else
{
  tested = aix_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ntp.rte");
}
