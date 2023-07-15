#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:2583-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(140481);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/10");

  script_name(english:"SUSE SLES15 Security Update : avahi (SUSE-SU-2020:2583-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for avahi fixes the following issues :

When changing ownership of /var/lib/autoipd, only change ownership of
files owned by avahi, to mitigate against possible exploits
(bsc#1154063).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1154063"
  );
  # https://www.suse.com/support/update/announcement/2020/suse-su-20202583-1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?058312ac"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server for SAP 15 :

zypper in -t patch SUSE-SLE-Product-SLES_SAP-15-2020-2583=1

SUSE Linux Enterprise Server 15-LTSS :

zypper in -t patch SUSE-SLE-Product-SLES-15-2020-2583=1

SUSE Linux Enterprise High Performance Computing 15-LTSS :

zypper in -t patch SUSE-SLE-Product-HPC-15-2020-2583=1

SUSE Linux Enterprise High Performance Computing 15-ESPOS :

zypper in -t patch SUSE-SLE-Product-HPC-15-2020-2583=1"
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:avahi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:avahi-compat-howl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:avahi-compat-mDNSResponder-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:avahi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:avahi-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:avahi-glib2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:avahi-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:avahi-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavahi-client3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavahi-client3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavahi-common3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavahi-common3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavahi-core7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavahi-core7-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavahi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavahi-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavahi-glib1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavahi-glib1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavahi-gobject0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavahi-gobject0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavahi-ui-gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavahi-ui-gtk3-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavahi-ui0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavahi-ui0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdns_sd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdns_sd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhowl0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhowl0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-Avahi");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "s390x") audit(AUDIT_ARCH_NOT, "s390x", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"avahi-0.6.32-5.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"avahi-compat-howl-devel-0.6.32-5.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"avahi-compat-mDNSResponder-devel-0.6.32-5.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"avahi-debuginfo-0.6.32-5.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"avahi-debugsource-0.6.32-5.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"avahi-glib2-debugsource-0.6.32-5.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"avahi-utils-0.6.32-5.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"avahi-utils-debuginfo-0.6.32-5.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libavahi-client3-0.6.32-5.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libavahi-client3-debuginfo-0.6.32-5.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libavahi-common3-0.6.32-5.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libavahi-common3-debuginfo-0.6.32-5.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libavahi-core7-0.6.32-5.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libavahi-core7-debuginfo-0.6.32-5.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libavahi-devel-0.6.32-5.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libavahi-glib-devel-0.6.32-5.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libavahi-glib1-0.6.32-5.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libavahi-glib1-debuginfo-0.6.32-5.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libavahi-gobject0-0.6.32-5.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libavahi-gobject0-debuginfo-0.6.32-5.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libavahi-ui-gtk3-0-0.6.32-5.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libavahi-ui-gtk3-0-debuginfo-0.6.32-5.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libavahi-ui0-0.6.32-5.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libavahi-ui0-debuginfo-0.6.32-5.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libdns_sd-0.6.32-5.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libdns_sd-debuginfo-0.6.32-5.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libhowl0-0.6.32-5.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libhowl0-debuginfo-0.6.32-5.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"typelib-1_0-Avahi-0_6-0.6.32-5.8.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "avahi");
}
