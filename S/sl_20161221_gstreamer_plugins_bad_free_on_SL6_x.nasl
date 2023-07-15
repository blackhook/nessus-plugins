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
  script_id(96041);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2016-9445", "CVE-2016-9447");

  script_name(english:"Scientific Linux Security Update : gstreamer-plugins-bad-free on SL6.x i386/x86_64 (20161221)");
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

  - An integer overflow flaw, leading to a heap-based buffer
    overflow, was found in GStreamer's VMware VMnc video
    file format decoding plug-in. A remote attacker could
    use this flaw to cause an application using GStreamer to
    crash or, potentially, execute arbitrary code with the
    privileges of the user running the application.
    (CVE-2016-9445)

  - A memory corruption flaw was found in GStreamer's
    Nintendo NSF music file format decoding plug-in. A
    remote attacker could use this flaw to cause an
    application using GStreamer to crash or, potentially,
    execute arbitrary code with the privileges of the user
    running the application. (CVE-2016-9447)

Note: This updates removes the vulnerable Nintendo NSF plug-in."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1612&L=scientific-linux-errata&F=&S=&P=17802
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ea9eb045"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gstreamer-plugins-bad-free");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gstreamer-plugins-bad-free-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gstreamer-plugins-bad-free-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gstreamer-plugins-bad-free-devel-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gstreamer-plugins-bad-free-extras");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/23");
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
if (rpm_check(release:"SL6", reference:"gstreamer-plugins-bad-free-0.10.19-5.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"gstreamer-plugins-bad-free-debuginfo-0.10.19-5.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"gstreamer-plugins-bad-free-devel-0.10.19-5.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"gstreamer-plugins-bad-free-devel-docs-0.10.19-5.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"gstreamer-plugins-bad-free-extras-0.10.19-5.el6_8")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gstreamer-plugins-bad-free / gstreamer-plugins-bad-free-debuginfo / etc");
}
