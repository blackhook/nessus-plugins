#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(110560);
  script_version("1.1");
  script_cvs_date("Date: 2018/06/15 13:36:38");

  script_cve_id("CVE-2013-6832","CVE-2013-6833","CVE-2013-6834");

  script_name(english:"FreeBSD < 10 qls_eioctl function Unauthorized Disclosure of Information");
  script_summary(english:"Checks for the version of the FreeBSD kernel.");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The qls_eioctl function in sys/dev/qlxge/qls_ioctl.c in the kernel 
in FreeBSD 10 and earlier does not validate a certain size parameter,
which allows local users to obtain sensitive information from kernel 
memory via a crafted ioctl call.");
  # http://archives.neohapsis.com/archives/fulldisclosure/2013-11/0107.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?20c6af1a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to FreeBSD version 10 or later");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/20");
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

fix = NULL;
if (release =~ "^FreeBSD-([0-9]|10\.[0-3])")
  fix = "FreeBSD-10.3_21";

if (isnull(fix) || pkg_cmp(pkg:release, reference:fix) >= 0)
  audit(AUDIT_HOST_NOT, "affected");

report =
  '\n  Installed version : ' + release +
  '\n  Fixed version     : ' + fix +
  '\n';
security_report_v4(port:0, severity:SECURITY_WARNING, extra:report);
