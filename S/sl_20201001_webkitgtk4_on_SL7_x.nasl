#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(141759);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/27");

  script_cve_id("CVE-2019-11070", "CVE-2019-6237", "CVE-2019-6251", "CVE-2019-8506", "CVE-2019-8524", "CVE-2019-8535", "CVE-2019-8536", "CVE-2019-8544", "CVE-2019-8551", "CVE-2019-8558", "CVE-2019-8559", "CVE-2019-8563", "CVE-2019-8571", "CVE-2019-8583", "CVE-2019-8584", "CVE-2019-8586", "CVE-2019-8587", "CVE-2019-8594", "CVE-2019-8595", "CVE-2019-8596", "CVE-2019-8597", "CVE-2019-8601", "CVE-2019-8607", "CVE-2019-8608", "CVE-2019-8609", "CVE-2019-8610", "CVE-2019-8611", "CVE-2019-8615", "CVE-2019-8619", "CVE-2019-8622", "CVE-2019-8623", "CVE-2019-8625", "CVE-2019-8644", "CVE-2019-8649", "CVE-2019-8658", "CVE-2019-8666", "CVE-2019-8669", "CVE-2019-8671", "CVE-2019-8672", "CVE-2019-8673", "CVE-2019-8674", "CVE-2019-8676", "CVE-2019-8677", "CVE-2019-8678", "CVE-2019-8679", "CVE-2019-8680", "CVE-2019-8681", "CVE-2019-8683", "CVE-2019-8684", "CVE-2019-8686", "CVE-2019-8687", "CVE-2019-8688", "CVE-2019-8689", "CVE-2019-8690", "CVE-2019-8707", "CVE-2019-8710", "CVE-2019-8719", "CVE-2019-8720", "CVE-2019-8726", "CVE-2019-8733", "CVE-2019-8735", "CVE-2019-8743", "CVE-2019-8763", "CVE-2019-8764", "CVE-2019-8765", "CVE-2019-8766", "CVE-2019-8768", "CVE-2019-8769", "CVE-2019-8771", "CVE-2019-8782", "CVE-2019-8783", "CVE-2019-8808", "CVE-2019-8811", "CVE-2019-8812", "CVE-2019-8813", "CVE-2019-8814", "CVE-2019-8815", "CVE-2019-8816", "CVE-2019-8819", "CVE-2019-8820", "CVE-2019-8821", "CVE-2019-8822", "CVE-2019-8823", "CVE-2019-8835", "CVE-2019-8844", "CVE-2019-8846", "CVE-2020-10018", "CVE-2020-11793", "CVE-2020-3862", "CVE-2020-3864", "CVE-2020-3865", "CVE-2020-3867", "CVE-2020-3868", "CVE-2020-3885", "CVE-2020-3894", "CVE-2020-3895", "CVE-2020-3897", "CVE-2020-3899", "CVE-2020-3900", "CVE-2020-3901", "CVE-2020-3902");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/25");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/13");

  script_name(english:"Scientific Linux Security Update : webkitgtk4 on SL7.x x86_64 (20201001)");
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

  - webkitgtk: Multiple security issues (CVE-2019-6237,
    CVE-2019-6251, CVE-2019-8506, CVE-2019-8524,
    CVE-2019-8535, CVE-2019-8536, CVE-2019-8544,
    CVE-2019-8551, CVE-2019-8558, CVE-2019-8559,
    CVE-2019-8563, CVE-2019-8571, CVE-2019-8583,
    CVE-2019-8584, CVE-2019-8586, CVE-2019-8587,
    CVE-2019-8594, CVE-2019-8595, CVE-2019-8596,
    CVE-2019-8597, CVE-2019-8601, CVE-2019-8607,
    CVE-2019-8608, CVE-2019-8609, CVE-2019-8610,
    CVE-2019-8611, CVE-2019-8615, CVE-2019-8619,
    CVE-2019-8622, CVE-2019-8623, CVE-2019-8625,
    CVE-2019-8644, CVE-2019-8649, CVE-2019-8658,
    CVE-2019-8666, CVE-2019-8669, CVE-2019-8671,
    CVE-2019-8672, CVE-2019-8673, CVE-2019-8674,
    CVE-2019-8676, CVE-2019-8677, CVE-2019-8678,
    CVE-2019-8679, CVE-2019-8680, CVE-2019-8681,
    CVE-2019-8683, CVE-2019-8684, CVE-2019-8686,
    CVE-2019-8687, CVE-2019-8688, CVE-2019-8689,
    CVE-2019-8690, CVE-2019-8707, CVE-2019-8710,
    CVE-2019-8719, CVE-2019-8720, CVE-2019-8726,
    CVE-2019-8733, CVE-2019-8735, CVE-2019-8743,
    CVE-2019-8763, CVE-2019-8764, CVE-2019-8765,
    CVE-2019-8766, CVE-2019-8768, CVE-2019-8769,
    CVE-2019-8771, CVE-2019-8782, CVE-2019-8783,
    CVE-2019-8808, CVE-2019-8811, CVE-2019-8812,
    CVE-2019-8813, CVE-2019-8814, CVE-2019-8815,
    CVE-2019-8816, CVE-2019-8819, CVE-2019-8820,
    CVE-2019-8821, CVE-2019-8822, CVE-2019-8823,
    CVE-2019-8835, CVE-2019-8844, CVE-2019-8846,
    CVE-2019-11070, CVE-2020-3862, CVE-2020-3864,
    CVE-2020-3865, CVE-2020-3867, CVE-2020-3868,
    CVE-2020-3885, CVE-2020-3894, CVE-2020-3895,
    CVE-2020-3897, CVE-2020-3899, CVE-2020-3900,
    CVE-2020-3901, CVE-2020-3902, CVE-2020-10018,
    CVE-2020-11793)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind2010&L=SCIENTIFIC-LINUX-ERRATA&P=5351
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?55230a62"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3899");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:webkitgtk4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:webkitgtk4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:webkitgtk4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:webkitgtk4-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:webkitgtk4-jsc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:webkitgtk4-jsc-devel");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"webkitgtk4-2.28.2-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"webkitgtk4-debuginfo-2.28.2-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"webkitgtk4-devel-2.28.2-2.el7")) flag++;
if (rpm_check(release:"SL7", reference:"webkitgtk4-doc-2.28.2-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"webkitgtk4-jsc-2.28.2-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"webkitgtk4-jsc-devel-2.28.2-2.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "webkitgtk4 / webkitgtk4-debuginfo / webkitgtk4-devel / etc");
}
