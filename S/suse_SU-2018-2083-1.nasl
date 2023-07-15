#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:2083-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(120065);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/20");

  script_cve_id("CVE-2018-2940", "CVE-2018-2952", "CVE-2018-2972", "CVE-2018-2973");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : java-10-openjdk (SUSE-SU-2018:2083-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for OpenJDK 10.0.2 fixes the following security issues :

  - CVE-2018-2940: the libraries sub-component contained an
    easily exploitable vulnerability that allowed attackers
    to compromise Java SE or Java SE Embedded over the
    network, potentially gaining unauthorized read access to
    data that's accessible to the server. [bsc#1101645]

  - CVE-2018-2952: the concurrency sub-component contained a
    difficult to exploit vulnerability that allowed
    attackers to compromise Java SE, Java SE Embedded, or
    JRockit over the network. This issue could have been
    abused to mount a partial denial-of-service attack on
    the server. [bsc#1101651]

  - CVE-2018-2972: the security sub-component contained a
    difficult to exploit vulnerability that allowed
    attackers to compromise Java SE over the network,
    potentially gaining unauthorized access to critical data
    or complete access to all Java SE accessible data.
    [bsc#1101655)

  - CVE-2018-2973: the JSSE sub-component contained a
    difficult to exploit vulnerability allowed attackers to
    compromise Java SE or Java SE Embedded over the network,
    potentially gaining the ability to create, delete or
    modify critical data or all Java SE, Java SE Embedded
    accessible data without authorization. [bsc#1101656]
    Furthemore, the following bugs were fixed :

  - Properly remove the existing alternative for java before
    reinstalling it. [bsc#1096420]

  - idlj was moved to the *-devel package. [bsc#1096420]

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1096420"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1101645"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1101651"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1101655"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1101656"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-2940/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-2952/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-2972/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-2973/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20182083-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b793135b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Basesystem 15:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-2018-1419=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-2973");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-10-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-10-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-10-openjdk-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-10-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-10-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-10-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(SLED15|SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED15 / SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"0", reference:"java-10-openjdk-10.0.2.0-3.3.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"java-10-openjdk-debuginfo-10.0.2.0-3.3.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"java-10-openjdk-debugsource-10.0.2.0-3.3.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"java-10-openjdk-demo-10.0.2.0-3.3.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"java-10-openjdk-devel-10.0.2.0-3.3.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"java-10-openjdk-headless-10.0.2.0-3.3.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"java-10-openjdk-10.0.2.0-3.3.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"java-10-openjdk-debuginfo-10.0.2.0-3.3.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"java-10-openjdk-debugsource-10.0.2.0-3.3.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"java-10-openjdk-demo-10.0.2.0-3.3.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"java-10-openjdk-devel-10.0.2.0-3.3.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"java-10-openjdk-headless-10.0.2.0-3.3.3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-10-openjdk");
}
