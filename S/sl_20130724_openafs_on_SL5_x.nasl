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
  script_id(69068);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-4134", "CVE-2013-4135");

  script_name(english:"Scientific Linux Security Update : openafs on SL5.x, SL6.x i386/x86_64 (20130724)");
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
"OpenAFS uses Kerberos tickets to secure network traffic. For
historical reasons, it has only supported the DES encryption algorithm
to encrypt these tickets. The weakness of DES's 56 bit key space has
long been known, however it has recently become possible to use that
weakness to cheaply (around $100) and rapidly (approximately 23 hours)
compromise a service's long term key. An attacker must first obtain a
ticket for the cell. They may then use a brute-force attack to
compromise the cell's private service key. Once an attacker has gained
access to the service key, they can use this to impersonate any user
within the cell, including the super user, giving them access to all
administrative capabilities as well as all user data. Recovering the
service key from a DES encrypted ticket is an issue for any Kerberos
service still using DES (and especially so for realms which still have
DES keys on their ticket granting ticket). (CVE-2013-4134)

The -encrypt option to the 'vos' volume management command should
cause it to encrypt all data between client and server. However, in
versions of OpenAFS later than 1.6.0, it has no effect, and data is
transmitted with integrity protection only. In all versions of
OpenAFS, vos -encrypt has no effect when combined with the -localauth
option. (CVE-2013-4135)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1307&L=scientific-linux-errata&T=0&P=1818
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?47d9be07"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kmod-openafs-358");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-authlibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-authlibs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-kpasswd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-module-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-plumbing-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-server");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/26");
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
if (rpm_check(release:"SL5", reference:"openafs-1.4.15-83.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-authlibs-1.4.15-83.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-authlibs-devel-1.4.15-83.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-client-1.4.15-83.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-compat-1.4.15-83.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-debug-1.4.15-83.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-devel-1.4.15-83.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-kernel-source-1.4.15-83.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-kpasswd-1.4.15-83.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-krb5-1.4.15-83.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-server-1.4.15-83.sl5")) flag++;

if (rpm_check(release:"SL6", reference:"kmod-openafs-358-1.6.5-145.sl6.358")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-1.6.5-145.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-authlibs-1.6.5-145.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-authlibs-devel-1.6.5-145.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-client-1.6.5-145.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-compat-1.6.5-145.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-devel-1.6.5-145.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-kernel-source-1.6.5-145.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-kpasswd-1.6.5-145.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-krb5-1.6.5-145.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-module-tools-1.6.5-145.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-plumbing-tools-1.6.5-145.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-server-1.6.5-145.sl6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kmod-openafs-358 / openafs / openafs-authlibs / etc");
}
