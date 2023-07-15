#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(84611);
  script_version("2.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2015-1869", "CVE-2015-1870", "CVE-2015-3142", "CVE-2015-3147", "CVE-2015-3159", "CVE-2015-3315");

  script_name(english:"Scientific Linux Security Update : abrt on SL6.x i386/x86_64 (20150707)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was found that ABRT was vulnerable to multiple race condition and
symbolic link flaws. A local attacker could use these flaws to
potentially escalate their privileges on the system. (CVE-2015-3315)

It was discovered that the kernel-invoked coredump processor provided
by ABRT wrote core dumps to files owned by other system users. This
could result in information disclosure if an application crashed while
its current directory was a directory writable to by other users (such
as /tmp). (CVE-2015-3142)

It was discovered that the default event handling scripts installed by
ABRT did not handle symbolic links correctly. A local attacker with
write access to an ABRT problem directory could use this flaw to
escalate their privileges. (CVE-2015-1869)

It was found that the ABRT event scripts created a user-readable copy
of an sosreport file in ABRT problem directories, and included
excerpts of /var/log/messages selected by the user-controlled process
name, leading to an information disclosure. (CVE-2015-1870)

It was discovered that, when moving problem reports between certain
directories, abrt-handle-upload did not verify that the new problem
directory had appropriate permissions and did not contain symbolic
links. An attacker able to create a crafted problem report could use
this flaw to expose other parts of ABRT, or to overwrite arbitrary
files on the system. (CVE-2015-3147)

It was discovered that the abrt-action-install-debuginfo-to-abrt-cache
helper program did not properly filter the process environment before
invoking abrt-action-install-debuginfo. A local attacker could use
this flaw to escalate their privileges on the system. (CVE-2015-3159)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1507&L=scientific-linux-errata&F=&S=&P=5735
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?53b73d62"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'ABRT raceabrt Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:abrt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:abrt-addon-ccpp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:abrt-addon-kerneloops");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:abrt-addon-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:abrt-addon-vmcore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:abrt-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:abrt-console-notification");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:abrt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:abrt-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:abrt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:abrt-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:abrt-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:abrt-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:abrt-tui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreport-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreport-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreport-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreport-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreport-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreport-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreport-gtk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreport-newt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreport-plugin-bugzilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreport-plugin-kerneloops");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreport-plugin-logger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreport-plugin-mailx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreport-plugin-reportuploader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreport-plugin-rhtsupport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreport-python");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/08");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
os_ver = pregmatch(pattern: "Scientific Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Scientific Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 6.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"abrt-2.0.8-26.el6_6.1")) flag++;
if (rpm_check(release:"SL6", reference:"abrt-addon-ccpp-2.0.8-26.el6_6.1")) flag++;
if (rpm_check(release:"SL6", reference:"abrt-addon-kerneloops-2.0.8-26.el6_6.1")) flag++;
if (rpm_check(release:"SL6", reference:"abrt-addon-python-2.0.8-26.el6_6.1")) flag++;
if (rpm_check(release:"SL6", reference:"abrt-addon-vmcore-2.0.8-26.el6_6.1")) flag++;
if (rpm_check(release:"SL6", reference:"abrt-cli-2.0.8-26.el6_6.1")) flag++;
if (rpm_check(release:"SL6", reference:"abrt-console-notification-2.0.8-26.el6_6.1")) flag++;
if (rpm_check(release:"SL6", reference:"abrt-debuginfo-2.0.8-26.el6_6.1")) flag++;
if (rpm_check(release:"SL6", reference:"abrt-desktop-2.0.8-26.el6_6.1")) flag++;
if (rpm_check(release:"SL6", reference:"abrt-devel-2.0.8-26.el6_6.1")) flag++;
if (rpm_check(release:"SL6", reference:"abrt-gui-2.0.8-26.el6_6.1")) flag++;
if (rpm_check(release:"SL6", reference:"abrt-libs-2.0.8-26.el6_6.1")) flag++;
if (rpm_check(release:"SL6", reference:"abrt-python-2.0.8-26.el6_6.1")) flag++;
if (rpm_check(release:"SL6", reference:"abrt-tui-2.0.8-26.el6_6.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreport-2.0.9-21.el6_6.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreport-cli-2.0.9-21.el6_6.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreport-compat-2.0.9-21.el6_6.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreport-debuginfo-2.0.9-21.el6_6.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreport-devel-2.0.9-21.el6_6.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreport-filesystem-2.0.9-21.el6_6.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreport-gtk-2.0.9-21.el6_6.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreport-gtk-devel-2.0.9-21.el6_6.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreport-newt-2.0.9-21.el6_6.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreport-plugin-bugzilla-2.0.9-21.el6_6.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreport-plugin-kerneloops-2.0.9-21.el6_6.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreport-plugin-logger-2.0.9-21.el6_6.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreport-plugin-mailx-2.0.9-21.el6_6.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreport-plugin-reportuploader-2.0.9-21.el6_6.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreport-plugin-rhtsupport-2.0.9-21.el6_6.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreport-python-2.0.9-21.el6_6.1")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "abrt / abrt-addon-ccpp / abrt-addon-kerneloops / abrt-addon-python / etc");
}
