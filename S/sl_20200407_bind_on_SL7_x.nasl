#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(135801);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/24");

  script_cve_id("CVE-2018-5745", "CVE-2019-6465", "CVE-2019-6477");

  script_name(english:"Scientific Linux Security Update : bind on SL7.x x86_64 (20200407)");
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
"* bind: TCP Pipelining doesn't limit TCP clients on a single
connection * bind: An assertion failure if a trust anchor rolls over
to an unsupported key algorithm when using managed-keys * bind:
Controls for zone transfers may not be properly applied to DLZs if the
zones are writable"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind2004&L=SCIENTIFIC-LINUX-ERRATA&P=4057
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?10669105"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-6465");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:bind-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:bind-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:bind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:bind-export-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:bind-export-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:bind-libs-lite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:bind-license");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:bind-lite-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:bind-pkcs11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:bind-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:bind-pkcs11-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:bind-pkcs11-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:bind-sdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:bind-sdb-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:bind-utils");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/21");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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


flag = 0;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"bind-9.11.4-16.P2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"bind-chroot-9.11.4-16.P2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"bind-debuginfo-9.11.4-16.P2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"bind-devel-9.11.4-16.P2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"bind-export-devel-9.11.4-16.P2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"bind-export-libs-9.11.4-16.P2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"bind-libs-9.11.4-16.P2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"bind-libs-lite-9.11.4-16.P2.el7")) flag++;
if (rpm_check(release:"SL7", reference:"bind-license-9.11.4-16.P2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"bind-license-9.11.4-16.P2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"bind-lite-devel-9.11.4-16.P2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"bind-pkcs11-9.11.4-16.P2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"bind-pkcs11-devel-9.11.4-16.P2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"bind-pkcs11-libs-9.11.4-16.P2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"bind-pkcs11-utils-9.11.4-16.P2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"bind-sdb-9.11.4-16.P2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"bind-sdb-chroot-9.11.4-16.P2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"bind-utils-9.11.4-16.P2.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind / bind-chroot / bind-debuginfo / bind-devel / etc");
}
