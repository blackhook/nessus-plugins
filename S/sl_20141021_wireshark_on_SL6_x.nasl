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
  script_id(78649);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2014-6421", "CVE-2014-6422", "CVE-2014-6423", "CVE-2014-6424", "CVE-2014-6425", "CVE-2014-6426", "CVE-2014-6427", "CVE-2014-6428", "CVE-2014-6429", "CVE-2014-6430", "CVE-2014-6431", "CVE-2014-6432");

  script_name(english:"Scientific Linux Security Update : wireshark on SL6.x, SL7.x i386/x86_64 (20141021)");
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
"Multiple flaws were found in Wireshark. If Wireshark read a malformed
packet off a network or opened a malicious dump file, it could crash
or, possibly, execute arbitrary code as the user running Wireshark.
(CVE-2014-6429, CVE-2014-6430, CVE-2014-6431, CVE-2014-6432)

Several denial of service flaws were found in Wireshark. Wireshark
could crash or stop responding if it read a malformed packet off a
network, or opened a malicious dump file. (CVE-2014-6421,
CVE-2014-6422, CVE-2014-6423, CVE-2014-6424, CVE-2014-6425,
CVE-2014-6426, CVE-2014-6427, CVE-2014-6428)

All running instances of Wireshark must be restarted for the update to
take effect."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1410&L=scientific-linux-errata&T=0&P=2400
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f54b7f92"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:wireshark-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:wireshark-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:wireshark-gnome");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/23");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL6", reference:"wireshark-1.8.10-8.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"wireshark-debuginfo-1.8.10-8.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"wireshark-devel-1.8.10-8.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"wireshark-gnome-1.8.10-8.el6_6")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"wireshark-1.10.3-12.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"wireshark-debuginfo-1.10.3-12.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"wireshark-devel-1.10.3-12.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"wireshark-gnome-1.10.3-12.el7_0")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wireshark / wireshark-debuginfo / wireshark-devel / wireshark-gnome");
}
