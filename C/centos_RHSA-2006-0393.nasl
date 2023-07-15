#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0393 and 
# CentOS Errata and Security Advisory 2006:0393 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(22275);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2005-2496");
  script_xref(name:"RHSA", value:"2006:0393");

  script_name(english:"CentOS 4 : ntp (CESA-2006:0393)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated ntp packages that fix several bugs are now available.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

The Network Time Protocol (NTP) is used to synchronize a computer's
time with a reference time source.

The NTP daemon (ntpd), when run with the -u option and using a string
to specify the group, uses the group ID of the user instead of the
group, which causes ntpd to run with different privileges than
intended. (CVE-2005-2496)

The following issues have also been addressed in this update: - The
init script had several problems - The script executed on upgrade
could fail - The man page for ntpd indicated the wrong option for
specifying a chroot directory - The ntp daemon could crash with the
message 'Exiting: No more memory!' - There is a new option for syncing
the hardware clock after a successful run of ntpdate

Users of ntp should upgrade to these updated packages, which resolve
these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-August/013151.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?53853f99"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-August/013152.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?47bc5d53"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-August/013170.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?09c2c482"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ntp package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ntp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/09/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/08/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/CentOS/release");
if (isnull(release) || "CentOS" >!< release) audit(AUDIT_OS_NOT, "CentOS");
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "CentOS");
os_ver = os_ver[1];
if (! preg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", reference:"ntp-4.2.0.a.20040617-4.EL4.1")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ntp");
}
