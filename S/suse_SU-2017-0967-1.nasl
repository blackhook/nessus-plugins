#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:0967-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(99263);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2017-5838");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : gstreamer (SUSE-SU-2017:0967-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for gstreamer fixes the following security issues :

  - A crafted AVI file could have caused an invalid memory
    read, possibly causing DoS or corruption (bsc#1024051,
    CVE-2017-5838)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1024051"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5838/"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20170967-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3e33d2bd"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP1:zypper in -t
patch SUSE-SLE-SDK-12-SP1-2017-562=1

SUSE Linux Enterprise Server 12-SP1:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2017-562=1

SUSE Linux Enterprise Desktop 12-SP1:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP1-2017-562=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gstreamer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gstreamer-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gstreamer-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gstreamer-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gstreamer-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstreamer-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstreamer-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstreamer-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-Gst");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP1", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", reference:"gstreamer-1.2.4-2.3.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"gstreamer-debuginfo-1.2.4-2.3.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"gstreamer-debugsource-1.2.4-2.3.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"gstreamer-utils-1.2.4-2.3.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"gstreamer-utils-debuginfo-1.2.4-2.3.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgstreamer-1_0-0-1.2.4-2.3.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgstreamer-1_0-0-debuginfo-1.2.4-2.3.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"typelib-1_0-Gst-1_0-1.2.4-2.3.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"gstreamer-debuginfo-32bit-1.2.4-2.3.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgstreamer-1_0-0-32bit-1.2.4-2.3.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgstreamer-1_0-0-debuginfo-32bit-1.2.4-2.3.3")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"gstreamer-1.2.4-2.3.3")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"gstreamer-debuginfo-1.2.4-2.3.3")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"gstreamer-debuginfo-32bit-1.2.4-2.3.3")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"gstreamer-debugsource-1.2.4-2.3.3")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"gstreamer-utils-1.2.4-2.3.3")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"gstreamer-utils-debuginfo-1.2.4-2.3.3")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgstreamer-1_0-0-1.2.4-2.3.3")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgstreamer-1_0-0-32bit-1.2.4-2.3.3")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgstreamer-1_0-0-debuginfo-1.2.4-2.3.3")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgstreamer-1_0-0-debuginfo-32bit-1.2.4-2.3.3")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"typelib-1_0-Gst-1_0-1.2.4-2.3.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gstreamer");
}
