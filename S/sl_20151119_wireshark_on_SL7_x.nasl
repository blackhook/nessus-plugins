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
  script_id(87578);
  script_version("2.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2014-8710", "CVE-2014-8711", "CVE-2014-8712", "CVE-2014-8713", "CVE-2014-8714", "CVE-2015-0562", "CVE-2015-0563", "CVE-2015-0564", "CVE-2015-2188", "CVE-2015-2189", "CVE-2015-2191", "CVE-2015-3182", "CVE-2015-3810", "CVE-2015-3811", "CVE-2015-3812", "CVE-2015-3813", "CVE-2015-6243", "CVE-2015-6244", "CVE-2015-6245", "CVE-2015-6246", "CVE-2015-6248");

  script_name(english:"Scientific Linux Security Update : wireshark on SL7.x x86_64 (20151119)");
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
"Several denial of service flaws were found in Wireshark. Wireshark
could crash or stop responding if it read a malformed packet off a
network, or opened a malicious dump file. (CVE-2015-2188,
CVE-2015-2189, CVE-2015-2191, CVE-2015-3810, CVE-2015-3811,
CVE-2015-3812, CVE-2015-3813, CVE-2014-8710, CVE-2014-8711,
CVE-2014-8712, CVE-2014-8713, CVE-2014-8714, CVE-2015-0562,
CVE-2015-0563, CVE-2015-0564, CVE-2015-3182, CVE-2015-6243,
CVE-2015-6244, CVE-2015-6245, CVE-2015-6246, CVE-2015-6248)

The wireshark packages have been upgraded to upstream version 1.10.14,
which provides a number of bug fixes and enhancements over the
previous version.

This update also fixes the following bug :

  - Prior to this update, when using the tshark utility to
    capture packets over the interface, tshark failed to
    create output files in the .pcap format even if it was
    specified using the '-F' option. This bug has been
    fixed, the '-F' option is now honored, and the result
    saved in the .pcap format as expected.

In addition, this update adds the following enhancement :

  - Previously, wireshark included only microseconds in the
    .pcapng format. With this update, wireshark supports
    nanosecond time stamp precision to allow for more
    accurate time stamps.

All running instances of Wireshark must be restarted for the update to
take effect."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1512&L=scientific-linux-errata&F=&S=&P=7014
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d419fdd2"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:wireshark-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:wireshark-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:wireshark-gnome");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"wireshark-1.10.14-7.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"wireshark-debuginfo-1.10.14-7.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"wireshark-devel-1.10.14-7.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"wireshark-gnome-1.10.14-7.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wireshark / wireshark-debuginfo / wireshark-devel / wireshark-gnome");
}
