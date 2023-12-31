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
  script_id(71192);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-0786", "CVE-2012-0787");

  script_name(english:"Scientific Linux Security Update : augeas on SL6.x i386/x86_64 (20131121)");
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
"Multiple flaws were found in the way Augeas handled configuration
files when updating them. An application using Augeas to update
configuration files in a directory that is writable to by a different
user (for example, an application running as root that is updating
files in a directory owned by a non-root service user) could have been
tricked into overwriting arbitrary files or leaking information via a
symbolic link or mount point attack. (CVE-2012-0786, CVE-2012-0787)

The augeas package has been upgraded to upstream version 1.0.0, which
provides a number of bug fixes and enhancements over the previous
version.

This update also fixes the following bugs :

  - Previously, when single quotes were used in an XML
    attribute, Augeas was unable to parse the file with the
    XML lens. An upstream patch has been provided ensuring
    that single quotes are handled as valid characters and
    parsing no longer fails.

  - Prior to this update, Augeas was unable to set up the
    'require_ssl_reuse' option in the vsftpd.conf file. The
    updated patch fixes the vsftpd lens to properly
    recognize this option, thus fixing this bug.

  - Previously, the XML lens did not support non-Unix line
    endings. Consequently, Augeas was unable to load any
    files containing such line endings. The XML lens has
    been fixed to handle files with CRLF line endings, thus
    fixing this bug.

  - Previously, Augeas was unable to parse modprobe.conf
    files with spaces around '=' characters in option
    directives. The modprobe lens has been updated and
    parsing no longer fails."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1312&L=scientific-linux-errata&T=0&P=79
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?701d9b5d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:augeas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:augeas-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:augeas-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:augeas-libs");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL6", reference:"augeas-1.0.0-5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"augeas-debuginfo-1.0.0-5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"augeas-devel-1.0.0-5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"augeas-libs-1.0.0-5.el6")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "augeas / augeas-debuginfo / augeas-devel / augeas-libs");
}
