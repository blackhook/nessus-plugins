#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(134070);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/14");

  script_cve_id("CVE-2019-16865", "CVE-2020-5312");

  script_name(english:"Scientific Linux Security Update : python-pillow on SL7.x x86_64 (20200224)");
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

python-pillow: improperly restricted operations on memory buffer in
libImaging/PcxDecode.c (CVE-2020-5312) python-pillow: reading
specially crafted image files leads to allocation of large amounts of
memory and denial of service (CVE-2019-16865)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind2002&L=SCIENTIFIC-LINUX-ERRATA&P=9993
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1db48eb2"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-5312");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python-pillow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python-pillow-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python-pillow-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python-pillow-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python-pillow-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python-pillow-sane");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python-pillow-tk");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/26");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-pillow-2.0.0-20.gitd1c6db8.el7_7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-pillow-debuginfo-2.0.0-20.gitd1c6db8.el7_7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-pillow-devel-2.0.0-20.gitd1c6db8.el7_7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-pillow-doc-2.0.0-20.gitd1c6db8.el7_7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-pillow-qt-2.0.0-20.gitd1c6db8.el7_7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-pillow-sane-2.0.0-20.gitd1c6db8.el7_7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-pillow-tk-2.0.0-20.gitd1c6db8.el7_7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-pillow / python-pillow-debuginfo / python-pillow-devel / etc");
}
