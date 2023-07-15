#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(135799);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/24");

  script_cve_id("CVE-2017-6519");

  script_name(english:"Scientific Linux Security Update : avahi on SL7.x x86_64 (20200407)");
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
"* avahi: Multicast DNS responds to unicast queries outside of local
network"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind2004&L=SCIENTIFIC-LINUX-ERRATA&P=3028
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cd5f6fbd"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:avahi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:avahi-autoipd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:avahi-compat-howl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:avahi-compat-howl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:avahi-compat-libdns_sd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:avahi-compat-libdns_sd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:avahi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:avahi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:avahi-dnsconfd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:avahi-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:avahi-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:avahi-gobject");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:avahi-gobject-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:avahi-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:avahi-qt3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:avahi-qt3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:avahi-qt4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:avahi-qt4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:avahi-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:avahi-ui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:avahi-ui-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:avahi-ui-gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:avahi-ui-tools");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/01");
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
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);


flag = 0;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"avahi-0.6.31-20.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"avahi-autoipd-0.6.31-20.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"avahi-compat-howl-0.6.31-20.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"avahi-compat-howl-devel-0.6.31-20.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"avahi-compat-libdns_sd-0.6.31-20.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"avahi-compat-libdns_sd-devel-0.6.31-20.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"avahi-debuginfo-0.6.31-20.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"avahi-devel-0.6.31-20.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"avahi-dnsconfd-0.6.31-20.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"avahi-glib-0.6.31-20.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"avahi-glib-devel-0.6.31-20.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"avahi-gobject-0.6.31-20.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"avahi-gobject-devel-0.6.31-20.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"avahi-libs-0.6.31-20.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"avahi-qt3-0.6.31-20.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"avahi-qt3-devel-0.6.31-20.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"avahi-qt4-0.6.31-20.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"avahi-qt4-devel-0.6.31-20.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"avahi-tools-0.6.31-20.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"avahi-ui-0.6.31-20.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"avahi-ui-devel-0.6.31-20.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"avahi-ui-gtk3-0.6.31-20.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"avahi-ui-tools-0.6.31-20.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "avahi / avahi-autoipd / avahi-compat-howl / avahi-compat-howl-devel / etc");
}
