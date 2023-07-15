#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(119249);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/02");

  script_cve_id("CVE-2018-15688");

  script_name(english:"Scientific Linux Security Update : NetworkManager on SL7.x x86_64 (20181127)");
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

  - systemd: Out-of-bounds heap write in systemd-networkd
    dhcpv6 option handling (CVE-2018-15688)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1811&L=scientific-linux-errata&F=&S=&P=15143
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d89b1b6c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15688");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:NetworkManager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:NetworkManager-adsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:NetworkManager-bluetooth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:NetworkManager-config-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:NetworkManager-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:NetworkManager-dispatcher-routing-rules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:NetworkManager-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:NetworkManager-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:NetworkManager-libnm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:NetworkManager-libnm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:NetworkManager-ovs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:NetworkManager-ppp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:NetworkManager-team");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:NetworkManager-tui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:NetworkManager-wifi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:NetworkManager-wwan");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/28");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"NetworkManager-1.12.0-8.el7_6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"NetworkManager-adsl-1.12.0-8.el7_6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"NetworkManager-bluetooth-1.12.0-8.el7_6")) flag++;
if (rpm_check(release:"SL7", reference:"NetworkManager-config-server-1.12.0-8.el7_6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"NetworkManager-debuginfo-1.12.0-8.el7_6")) flag++;
if (rpm_check(release:"SL7", reference:"NetworkManager-dispatcher-routing-rules-1.12.0-8.el7_6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"NetworkManager-glib-1.12.0-8.el7_6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"NetworkManager-glib-devel-1.12.0-8.el7_6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"NetworkManager-libnm-1.12.0-8.el7_6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"NetworkManager-libnm-devel-1.12.0-8.el7_6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"NetworkManager-ovs-1.12.0-8.el7_6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"NetworkManager-ppp-1.12.0-8.el7_6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"NetworkManager-team-1.12.0-8.el7_6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"NetworkManager-tui-1.12.0-8.el7_6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"NetworkManager-wifi-1.12.0-8.el7_6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"NetworkManager-wwan-1.12.0-8.el7_6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "NetworkManager / NetworkManager-adsl / NetworkManager-bluetooth / etc");
}
