#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:0269-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(88486);
  script_version("2.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2015-4871", "CVE-2015-7575", "CVE-2015-8126", "CVE-2015-8472", "CVE-2016-0402", "CVE-2016-0448", "CVE-2016-0466", "CVE-2016-0483", "CVE-2016-0494");

  script_name(english:"SUSE SLED11 Security Update : java-1_7_0-openjdk (SUSE-SU-2016:0269-1) (SLOTH)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"java-1_7_0-openjdk was updated to version 7u95 to fix 9 security
issues. (bsc#962743)

  - CVE-2015-4871: Rebinding of the receiver of a
    DirectMethodHandle may allow a protected method to be
    accessed

  - CVE-2015-7575: Further reduce use of MD5 (SLOTH)
    (bsc#960996)

  - CVE-2015-8126: Vulnerability in the AWT component
    related to splashscreen displays

  - CVE-2015-8472: Vulnerability in the AWT component,
    addressed by same fix

  - CVE-2016-0402: Vulnerability in the Networking component
    related to URL processing

  - CVE-2016-0448: Vulnerability in the JMX comonent related
    to attribute processing

  - CVE-2016-0466: Vulnerability in the JAXP component,
    related to limits

  - CVE-2016-0483: Vulnerability in the AWT component
    related to image decoding

  - CVE-2016-0494: Vulnerability in 2D component related to
    font actions

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=960996"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=962743"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4871/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7575/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8126/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8472/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0402/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0448/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0466/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0483/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0494/"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20160269-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?29141d30"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Desktop 11-SP4 :

zypper in -t patch sledsp4-java-1_7_0-openjdk-12374=1

SUSE Linux Enterprise Desktop 11-SP3 :

zypper in -t patch sledsp3-java-1_7_0-openjdk-12374=1

SUSE Linux Enterprise Debuginfo 11-SP4 :

zypper in -t patch dbgsp4-java-1_7_0-openjdk-12374=1

SUSE Linux Enterprise Debuginfo 11-SP3 :

zypper in -t patch dbgsp3-java-1_7_0-openjdk-12374=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/29");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(SLED11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "i386|i486|i586|i686|x86_64") audit(AUDIT_ARCH_NOT, "i386 / i486 / i586 / i686 / x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLED11" && (! preg(pattern:"^(3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLED11 SP3/4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"java-1_7_0-openjdk-1.7.0.95-0.17.2")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"java-1_7_0-openjdk-demo-1.7.0.95-0.17.2")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"java-1_7_0-openjdk-devel-1.7.0.95-0.17.2")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"java-1_7_0-openjdk-1.7.0.95-0.17.2")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"java-1_7_0-openjdk-demo-1.7.0.95-0.17.2")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"java-1_7_0-openjdk-devel-1.7.0.95-0.17.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"java-1_7_0-openjdk-1.7.0.95-0.17.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"java-1_7_0-openjdk-demo-1.7.0.95-0.17.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"java-1_7_0-openjdk-devel-1.7.0.95-0.17.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"java-1_7_0-openjdk-1.7.0.95-0.17.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"java-1_7_0-openjdk-demo-1.7.0.95-0.17.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"java-1_7_0-openjdk-devel-1.7.0.95-0.17.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1_7_0-openjdk");
}
