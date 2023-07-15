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
  script_id(87571);
  script_version("2.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2015-2704");

  script_name(english:"Scientific Linux Security Update : realmd on SL7.x x86_64 (20151119)");
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
"A flaw was found in the way realmd parsed certain input when writing
configuration into the sssd.conf or smb.conf file. A remote attacker
could use this flaw to inject arbitrary configurations into these
files via a newline character in an LDAP response. (CVE-2015-2704)

It was found that the realm client would try to automatically join an
active directory domain without authentication, which could
potentially lead to privilege escalation within a specified domain.

The realmd packages have been upgraded to upstream version 0.16.1,
which provides a number of bug fixes and enhancements over the
previous version.

This update also fixes the following bugs :

  - Joining a Scientific Linux machine to a domain using the
    realm utility creates /home/domainname/[username]/
    directories for domain users. Previously, SELinux
    labeled the domain users' directories incorrectly. As a
    consequence, the domain users sometimes experienced
    problems with SELinux policy. This update modifies the
    realmd service default behavior so that the domain
    users' directories are compatible with the standard
    SELinux policy.

  - Previously, the realm utility was unable to join or
    discover domains with domain names containing underscore
    (_). The realmd service has been modified to process
    underscores in domain names correctly, which fixes the
    described bug.

In addition, this update adds the following enhancement :

  - The realmd utility now allows the user to disable
    automatic ID mapping from the command line. To disable
    the mapping, pass the '--automatic-id- mapping=no'
    option to the realmd utility."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1512&L=scientific-linux-errata&F=&S=&P=16562
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?950ca40d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected realmd, realmd-debuginfo and / or
realmd-devel-docs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:realmd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:realmd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:realmd-devel-docs");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/22");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 7.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);


flag = 0;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"realmd-0.16.1-5.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"realmd-debuginfo-0.16.1-5.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"realmd-devel-docs-0.16.1-5.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "realmd / realmd-debuginfo / realmd-devel-docs");
}
