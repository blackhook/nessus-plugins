#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(141689);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/28");

  script_cve_id("CVE-2019-11719", "CVE-2019-11727", "CVE-2019-11756", "CVE-2019-17006", "CVE-2019-17023", "CVE-2020-12400", "CVE-2020-12401", "CVE-2020-12402", "CVE-2020-12403", "CVE-2020-6829");

  script_name(english:"Scientific Linux Security Update : nss and nspr on SL7.x x86_64 (20201001)");
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
"Security Fix(es) :

  - nss: Out-of-bounds read when importing curve25519
    private key (CVE-2019-11719)

  - nss: Use-after-free in sftk_FreeSession due to improper
    refcounting (CVE-2019-11756)

  - nss: Check length of inputs for cryptographic primitives
    (CVE-2019-17006)

  - nss: Side channel attack on ECDSA signature generation
    (CVE-2020-6829)

  - nss: P-384 and P-521 implementation uses a side-channel
    vulnerable modular inversion function (CVE-2020-12400)

  - nss: ECDSA timing attack mitigation bypass
    (CVE-2020-12401)

  - nss: Side channel vulnerabilities during RSA key
    generation (CVE-2020-12402)

  - nss: CHACHA20-POLY1305 decryption with undersized tag
    leads to out-of-bounds read (CVE-2020-12403)

  - nss: PKCS#1 v1.5 signatures can be used for TLS 1.3
    (CVE-2019-11727)

  - nss: TLS 1.3 HelloRetryRequest downgrade request sets
    client into invalid state (CVE-2019-17023)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind2010&L=SCIENTIFIC-LINUX-ERRATA&P=14301
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d878e66a"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17006");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:nspr-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:nss-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:nss-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:nss-softokn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:nss-softokn-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:nss-softokn-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:nss-softokn-freebl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:nss-softokn-freebl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:nss-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:nss-util-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:nss-util-devel");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/21");
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
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);


flag = 0;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nspr-4.25.0-2.el7_9")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nspr-debuginfo-4.25.0-2.el7_9")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nspr-devel-4.25.0-2.el7_9")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-3.53.1-3.el7_9")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-debuginfo-3.53.1-3.el7_9")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-devel-3.53.1-3.el7_9")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-pkcs11-devel-3.53.1-3.el7_9")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-softokn-3.53.1-6.el7_9")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-softokn-debuginfo-3.53.1-6.el7_9")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-softokn-devel-3.53.1-6.el7_9")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-softokn-freebl-3.53.1-6.el7_9")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-softokn-freebl-devel-3.53.1-6.el7_9")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-sysinit-3.53.1-3.el7_9")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-tools-3.53.1-3.el7_9")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-util-3.53.1-1.el7_9")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-util-debuginfo-3.53.1-1.el7_9")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-util-devel-3.53.1-1.el7_9")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nspr / nspr-debuginfo / nspr-devel / nss / nss-debuginfo / etc");
}
