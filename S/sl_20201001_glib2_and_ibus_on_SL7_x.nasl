#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(141664);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/23");

  script_cve_id("CVE-2019-12450", "CVE-2019-14822");

  script_name(english:"Scientific Linux Security Update : glib2 and ibus on SL7.x x86_64 (20201001)");
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

  - glib2: file_copy_fallback in gio/gfile.c in GNOME GLib
    does not properly restrict file permissions while a copy
    operation is in progress (CVE-2019-12450)

  - ibus: missing authorization allows local attacker to
    access the input bus of another user (CVE-2019-14822)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind2010&L=SCIENTIFIC-LINUX-ERRATA&P=21267
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e805c554"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:glib2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:glib2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:glib2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:glib2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:glib2-fam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:glib2-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:glib2-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ibus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ibus-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ibus-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ibus-devel-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ibus-gtk2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ibus-gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ibus-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ibus-pygtk2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ibus-setup");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/29");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"glib2-2.56.1-7.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"glib2-debuginfo-2.56.1-7.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"glib2-devel-2.56.1-7.el7")) flag++;
if (rpm_check(release:"SL7", reference:"glib2-doc-2.56.1-7.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"glib2-fam-2.56.1-7.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"glib2-static-2.56.1-7.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"glib2-tests-2.56.1-7.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ibus-1.5.17-11.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ibus-debuginfo-1.5.17-11.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ibus-devel-1.5.17-11.el7")) flag++;
if (rpm_check(release:"SL7", reference:"ibus-devel-docs-1.5.17-11.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ibus-gtk2-1.5.17-11.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ibus-gtk3-1.5.17-11.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ibus-libs-1.5.17-11.el7")) flag++;
if (rpm_check(release:"SL7", reference:"ibus-pygtk2-1.5.17-11.el7")) flag++;
if (rpm_check(release:"SL7", reference:"ibus-setup-1.5.17-11.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ibus-setup-1.5.17-11.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glib2 / glib2-debuginfo / glib2-devel / glib2-doc / glib2-fam / etc");
}
