
include("compat.inc");

if (description)
{
  script_id(110559);
  script_version("1.2");
  script_cvs_date("Date: 2018/06/18 11:51:45");

  script_cve_id("CVE-2011-4062");
  script_bugtraq_id(49862);
  script_xref(name:"EDB-ID", value:"17908");

  script_name(english:"FreeBSD 7.3 to 9.0-RC1 privilege escalation/denial of service");
  script_summary(english:"Checks for the version of the FreeBSD kernel.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Buffer overflow in the 'Linux emulation' support in FreeBSD kernel
allows local users to cause a denial of service (panic) and possibly
execute arbitrary code by calling the bind system call with a long
path for a UNIX-domain socket, which is not properly handled when the
address is used by other unspecified system calls."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://secunia.com/advisories/46564"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://secunia.com/advisories/46202"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://security.freebsd.org/advisories/FreeBSD-SA-11:05.unix.asc"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securitytracker.com/id?10261062"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade your vulnerable system to 7-STABLE or 8-STABLE, or to
the RELENG_8_2, RELENG_8_1, RELENG_7_4, or RELENG_7_3 security
branch dated after the correction date."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vuln_publication_date", value:"2011/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_end_attributes();
  
  script_category(ACT_GATHER_INFO);
  script_family(english:"FreeBSD Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/FreeBSD/release", "Host/FreeBSD/pkg_info", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("freebsd_package.inc");
include("misc_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/FreeBSD/release");

#grab the telnet banner to check
if (!release) 
    audit(AUDIT_OS_NOT, "FreeBSD");

if (!get_kb_item("Host/FreeBSD/pkg_info")) audit(AUDIT_PACKAGE_LIST_MISSING);

# Patches are available and ipfilter must be enabled with
# "keep state" or "keep frags" rule options enabled
if (report_paranoia < 2) audit(AUDIT_PARANOID);


#Affects:        All supported versions of FreeBSD.
#Corrected:      2011-10-04 19:07:38 UTC (RELENG_7, 7.4-STABLE)
#                2011-10-04 19:07:38 UTC (RELENG_7_4, 7.4-RELEASE-p4)
#                2011-10-04 19:07:38 UTC (RELENG_7_3, 7.3-RELEASE-p8)
#                2011-10-04 19:07:38 UTC (RELENG_8, 8.2-STABLE)
#                2011-10-04 19:07:38 UTC (RELENG_8_2, 8.2-RELEASE-p4)
#                2011-10-04 19:07:38 UTC (RELENG_8_1, 8.1-RELEASE-p6)
#                2011-10-04 19:07:38 UTC (RELENG_9, 9.0-RC1)
fix = NULL;

if (release =~ "^FreeBSD-7\.0($|[^0-9])")
  fix = "FreeBSD-7.4-STABLE";
else if (release =~ "^FreeBSD-7\.4($|[^0-9])" && !(release =~ "^FreeBSD-7\.4-STABLE") && !(release =~ "^FreeBSD-7\.4-RELEASE-p4"))
  fix = "FreeBSD-7.4-RELEASE-p4";
else if (release =~ "^FreeBSD-7\.3($|[^0-9])" && !(release =~ "^FreeBSD-7\.3-RELEASE-p8"))
  fix = "FreeBSD-7.3-RELEASE-p8";
else if (release =~ "^FreeBSD-8\.0($|[^0-9])")
  fix = "FreeBSD-8.2-STABLE";
else if (release =~ "^FreeBSD-8\.2($|[^0-9])" && !(release =~ "^FreeBSD-8\.2-STABLE") && !(release =~ "^FreeBSD-8\.2-RELEASE-p4"))
  fix = "FreeBSD-8.2-RELEASE-p4";
else if (release =~ "^FreeBSD-8\.1($|[^0-9])" && !(release =~ "^FreeBSD-8\.1-RELEASE-p6"))
  fix = "FreeBSD-8.1-RELEASE-p6";
else if (release =~ "^FreeBSD-(9\.0)($|[^0-9])" && !(release =~ "^FreeBSD-9\.0-RC1"))
  fix = "FreeBSD-9.0-RC1";

if (isnull(fix))
  audit(AUDIT_HOST_NOT, "affected");

report =
  '\n  Installed version : ' + release +
  '\n  Fixed version     : ' + fix +
  '\n';
security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
