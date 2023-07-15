#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(141653);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/23");

  script_cve_id("CVE-2019-15691", "CVE-2019-15692", "CVE-2019-15693", "CVE-2019-15694", "CVE-2019-15695");

  script_name(english:"Scientific Linux Security Update : tigervnc on SL7.x x86_64 (20201001)");
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

  - tigervnc: Stack use-after-return due to incorrect usage
    of stack memory in ZRLEDecoder (CVE-2019-15691)

  - tigervnc: Heap buffer overflow triggered from
    CopyRectDecoder due to incorrect value checks
    (CVE-2019-15692)

  - tigervnc: Heap buffer overflow in
    TightDecoder::FilterGradient (CVE-2019-15693)

  - tigervnc: Heap buffer overflow in
    DecodeManager::decodeRect (CVE-2019-15694)

  - tigervnc: Stack buffer overflow in
    CMsgReader::readSetCursor (CVE-2019-15695)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind2010&L=SCIENTIFIC-LINUX-ERRATA&P=2645
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6f33ff44"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tigervnc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tigervnc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tigervnc-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tigervnc-license");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tigervnc-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tigervnc-server-applet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tigervnc-server-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tigervnc-server-module");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/26");
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


flag = 0;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"tigervnc-1.8.0-21.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"tigervnc-debuginfo-1.8.0-21.el7")) flag++;
if (rpm_check(release:"SL7", reference:"tigervnc-icons-1.8.0-21.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"tigervnc-icons-1.8.0-21.el7")) flag++;
if (rpm_check(release:"SL7", reference:"tigervnc-license-1.8.0-21.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"tigervnc-license-1.8.0-21.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"tigervnc-server-1.8.0-21.el7")) flag++;
if (rpm_check(release:"SL7", reference:"tigervnc-server-applet-1.8.0-21.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"tigervnc-server-minimal-1.8.0-21.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"tigervnc-server-module-1.8.0-21.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tigervnc / tigervnc-debuginfo / tigervnc-icons / tigervnc-license / etc");
}
