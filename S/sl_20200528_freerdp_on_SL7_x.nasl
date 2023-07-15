#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(137040);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/28");

  script_cve_id("CVE-2020-11521", "CVE-2020-11523", "CVE-2020-11524");

  script_name(english:"Scientific Linux Security Update : freerdp on SL7.x x86_64 (20200528)");
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

  - freerdp: Out-of-bounds write in planar.c
    (CVE-2020-11521)

  - freerdp: Integer overflow in region.c (CVE-2020-11523)

  - freerdp: Out-of-bounds write in interleaved.c
    (CVE-2020-11524)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind2006&L=SCIENTIFIC-LINUX-ERRATA&P=75
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cc05ae3b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11524");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:freerdp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:freerdp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:freerdp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:freerdp-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libwinpr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libwinpr-devel");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/02");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"freerdp-2.0.0-4.rc4.el7_8")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"freerdp-debuginfo-2.0.0-4.rc4.el7_8")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"freerdp-devel-2.0.0-4.rc4.el7_8")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"freerdp-libs-2.0.0-4.rc4.el7_8")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libwinpr-2.0.0-4.rc4.el7_8")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libwinpr-devel-2.0.0-4.rc4.el7_8")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "freerdp / freerdp-debuginfo / freerdp-devel / freerdp-libs / etc");
}
