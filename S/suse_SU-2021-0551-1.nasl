#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2021:0551-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(146794);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/01");

  script_cve_id("CVE-2021-26720");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : avahi (SUSE-SU-2021:0551-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for avahi fixes the following issues :

CVE-2021-26720: drop privileges when invoking
avahi-daemon-check-dns.sh (bsc#1180827)

Update avahi-daemon-check-dns.sh from Debian. Our previous version
relied on ifconfig, route, and init.d.

Add sudo to requires: used to drop privileges.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1180827"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2021-26720/"
  );
  # https://www.suse.com/support/update/announcement/2021/suse-su-20210551-1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ff1b319e"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP2 :

zypper in -t patch
SUSE-SLE-Module-Packagehub-Subpackages-15-SP2-2021-551=1

SUSE Linux Enterprise Module for Desktop Applications 15-SP2 :

zypper in -t patch
SUSE-SLE-Module-Desktop-Applications-15-SP2-2021-551=1

SUSE Linux Enterprise Module for Basesystem 15-SP2 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-SP2-2021-551=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-26720");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:avahi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:avahi-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:avahi-autoipd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:avahi-autoipd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:avahi-compat-howl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:avahi-compat-mDNSResponder-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:avahi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:avahi-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:avahi-glib2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:avahi-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:avahi-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:avahi-utils-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:avahi-utils-gtk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavahi-client3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavahi-client3-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavahi-client3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavahi-common3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavahi-common3-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavahi-common3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavahi-core7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavahi-core7-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavahi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavahi-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavahi-glib1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavahi-glib1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavahi-gobject-devel");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-avahi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-Avahi");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/24");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver == "SLES15" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP2", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"avahi-32bit-debuginfo-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libavahi-client3-32bit-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libavahi-client3-32bit-debuginfo-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libavahi-common3-32bit-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libavahi-common3-32bit-debuginfo-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"avahi-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"avahi-autoipd-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"avahi-autoipd-debuginfo-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"avahi-compat-howl-devel-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"avahi-compat-mDNSResponder-devel-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"avahi-debuginfo-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"avahi-debugsource-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"avahi-glib2-debugsource-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"avahi-utils-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"avahi-utils-debuginfo-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"avahi-utils-gtk-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"avahi-utils-gtk-debuginfo-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libavahi-client3-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libavahi-client3-debuginfo-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libavahi-common3-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libavahi-common3-debuginfo-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libavahi-core7-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libavahi-core7-debuginfo-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libavahi-devel-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libavahi-glib-devel-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libavahi-glib1-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libavahi-glib1-debuginfo-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libavahi-gobject-devel-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libavahi-gobject0-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libavahi-gobject0-debuginfo-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libavahi-ui-gtk3-0-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libavahi-ui-gtk3-0-debuginfo-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libavahi-ui0-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libavahi-ui0-debuginfo-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libdns_sd-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libdns_sd-debuginfo-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libhowl0-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libhowl0-debuginfo-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"python3-avahi-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"typelib-1_0-Avahi-0_6-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"avahi-32bit-debuginfo-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libavahi-client3-32bit-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libavahi-client3-32bit-debuginfo-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libavahi-common3-32bit-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libavahi-common3-32bit-debuginfo-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"avahi-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"avahi-autoipd-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"avahi-autoipd-debuginfo-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"avahi-compat-howl-devel-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"avahi-compat-mDNSResponder-devel-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"avahi-debuginfo-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"avahi-debugsource-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"avahi-glib2-debugsource-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"avahi-utils-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"avahi-utils-debuginfo-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"avahi-utils-gtk-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"avahi-utils-gtk-debuginfo-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libavahi-client3-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libavahi-client3-debuginfo-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libavahi-common3-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libavahi-common3-debuginfo-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libavahi-core7-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libavahi-core7-debuginfo-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libavahi-devel-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libavahi-glib-devel-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libavahi-glib1-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libavahi-glib1-debuginfo-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libavahi-gobject-devel-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libavahi-gobject0-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libavahi-gobject0-debuginfo-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libavahi-ui-gtk3-0-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libavahi-ui-gtk3-0-debuginfo-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libavahi-ui0-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libavahi-ui0-debuginfo-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libdns_sd-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libdns_sd-debuginfo-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libhowl0-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libhowl0-debuginfo-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"python3-avahi-0.7-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"typelib-1_0-Avahi-0_6-0.7-3.6.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "avahi");
}
