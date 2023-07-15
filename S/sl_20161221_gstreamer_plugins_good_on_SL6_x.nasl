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
  script_id(96042);
  script_version("3.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2016-9634", "CVE-2016-9635", "CVE-2016-9636", "CVE-2016-9807", "CVE-2016-9808");

  script_name(english:"Scientific Linux Security Update : gstreamer-plugins-good on SL6.x i386/x86_64 (20161221)");
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

  - Multiple flaws were discovered in GStreamer's
    FLC/FLI/FLX media file format decoding plug-in. A remote
    attacker could use these flaws to cause an application
    using GStreamer to crash or, potentially, execute
    arbitrary code with the privileges of the user running
    the application. (CVE-2016-9634, CVE-2016-9635,
    CVE-2016-9636, CVE-2016-9808)

  - An invalid memory read access flaw was found in
    GStreamer's FLC/FLI/FLX media file format decoding
    plug-in. A remote attacker could use this flaw to cause
    an application using GStreamer to crash. (CVE-2016-9807)

Note: This updates removes the vulnerable FLC/FLI/FLX plug-in."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1612&L=scientific-linux-errata&F=&S=&P=18190
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?66b88a0f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected gstreamer-plugins-good,
gstreamer-plugins-good-debuginfo and / or gstreamer-plugins-good-devel
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gstreamer-plugins-good");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gstreamer-plugins-good-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gstreamer-plugins-good-devel");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/21");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 6.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"gstreamer-plugins-good-0.10.23-4.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"gstreamer-plugins-good-debuginfo-0.10.23-4.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"gstreamer-plugins-good-devel-0.10.23-4.el6_8")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gstreamer-plugins-good / gstreamer-plugins-good-debuginfo / etc");
}
