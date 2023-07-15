#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:0336-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(122148);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/10");

  script_cve_id("CVE-2018-18500", "CVE-2018-18501", "CVE-2018-18505");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : MozillaFirefox (SUSE-SU-2019:0336-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for MozillaFirefox fixes the following issues :

Security issues fixed :

  - CVE-2018-18500: Fixed a use-after-free parsing HTML5
    stream (boo#1122983).

  - CVE-2018-18501: Fixed multiple memory safety bugs
    (boo#1122983).

  - CVE-2018-18505: Fixed a privilege escalation through IPC
    channel messages (boo#1122983).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1120374"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1122983"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-18500/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-18501/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-18505/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20190336-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7ad1d3cd"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud 7:zypper in -t patch
SUSE-OpenStack-Cloud-7-2019-336=1

SUSE Linux Enterprise Software Development Kit 12-SP4:zypper in -t
patch SUSE-SLE-SDK-12-SP4-2019-336=1

SUSE Linux Enterprise Software Development Kit 12-SP3:zypper in -t
patch SUSE-SLE-SDK-12-SP3-2019-336=1

SUSE Linux Enterprise Server for SAP 12-SP2:zypper in -t patch
SUSE-SLE-SAP-12-SP2-2019-336=1

SUSE Linux Enterprise Server 12-SP4:zypper in -t patch
SUSE-SLE-SERVER-12-SP4-2019-336=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2019-336=1

SUSE Linux Enterprise Server 12-SP2-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2019-336=1

SUSE Linux Enterprise Server 12-SP2-BCL:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-BCL-2019-336=1

SUSE Linux Enterprise Server 12-SP1-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2019-336=1

SUSE Linux Enterprise Server 12-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-2019-336=1

SUSE Linux Enterprise Desktop 12-SP4:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP4-2019-336=1

SUSE Linux Enterprise Desktop 12-SP3:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP3-2019-336=1

SUSE Enterprise Storage 4:zypper in -t patch SUSE-Storage-4-2019-336=1

SUSE CaaS Platform ALL :

To install this update, use the SUSE CaaS Platform Velum dashboard. It
will inform you if it detects new updates and let you then trigger
updating of the complete cluster in a controlled way.

SUSE CaaS Platform 3.0 :

To install this update, use the SUSE CaaS Platform Velum dashboard. It
will inform you if it detects new updates and let you then trigger
updating of the complete cluster in a controlled way."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-branding-SLE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfreebl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfreebl3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfreebl3-hmac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsoftokn3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsoftokn3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsoftokn3-hmac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-certs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-certs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-sysinit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/13");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver == "SLES12" && (! preg(pattern:"^(0|1|2|3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0/1/2/3/4", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP3/4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", reference:"MozillaFirefox-60.5.0esr-109.58.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"MozillaFirefox-branding-SLE-60-32.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"MozillaFirefox-debuginfo-60.5.0esr-109.58.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"MozillaFirefox-debugsource-60.5.0esr-109.58.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"MozillaFirefox-devel-60.5.0esr-109.58.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"MozillaFirefox-translations-common-60.5.0esr-109.58.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libfreebl3-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libfreebl3-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libfreebl3-debuginfo-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libfreebl3-debuginfo-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libfreebl3-hmac-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libfreebl3-hmac-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsoftokn3-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsoftokn3-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsoftokn3-debuginfo-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsoftokn3-debuginfo-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsoftokn3-hmac-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsoftokn3-hmac-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nss-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nss-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nss-certs-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nss-certs-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nss-certs-debuginfo-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nss-certs-debuginfo-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nss-debuginfo-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nss-debuginfo-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nss-debugsource-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nss-devel-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nss-sysinit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nss-sysinit-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nss-sysinit-debuginfo-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nss-tools-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nss-tools-debuginfo-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"MozillaFirefox-60.5.0esr-109.58.3")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"MozillaFirefox-branding-SLE-60-32.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"MozillaFirefox-debuginfo-60.5.0esr-109.58.3")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"MozillaFirefox-debugsource-60.5.0esr-109.58.3")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"MozillaFirefox-translations-common-60.5.0esr-109.58.3")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libfreebl3-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libfreebl3-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libfreebl3-debuginfo-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libfreebl3-debuginfo-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libfreebl3-hmac-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libfreebl3-hmac-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libsoftokn3-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libsoftokn3-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libsoftokn3-debuginfo-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libsoftokn3-debuginfo-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libsoftokn3-hmac-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libsoftokn3-hmac-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"mozilla-nss-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"mozilla-nss-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"mozilla-nss-certs-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"mozilla-nss-certs-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"mozilla-nss-certs-debuginfo-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"mozilla-nss-certs-debuginfo-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"mozilla-nss-debuginfo-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"mozilla-nss-debuginfo-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"mozilla-nss-debugsource-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"mozilla-nss-sysinit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"mozilla-nss-sysinit-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"mozilla-nss-sysinit-debuginfo-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"mozilla-nss-tools-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"mozilla-nss-tools-debuginfo-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"MozillaFirefox-60.5.0esr-109.58.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"MozillaFirefox-branding-SLE-60-32.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"MozillaFirefox-debuginfo-60.5.0esr-109.58.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"MozillaFirefox-debugsource-60.5.0esr-109.58.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"MozillaFirefox-devel-60.5.0esr-109.58.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"MozillaFirefox-translations-common-60.5.0esr-109.58.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libfreebl3-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libfreebl3-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libfreebl3-debuginfo-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libfreebl3-debuginfo-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libfreebl3-hmac-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libfreebl3-hmac-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsoftokn3-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsoftokn3-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsoftokn3-debuginfo-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsoftokn3-debuginfo-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsoftokn3-hmac-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsoftokn3-hmac-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nss-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nss-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nss-certs-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nss-certs-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nss-certs-debuginfo-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nss-certs-debuginfo-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nss-debuginfo-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nss-debuginfo-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nss-debugsource-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nss-devel-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nss-sysinit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nss-sysinit-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nss-sysinit-debuginfo-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nss-tools-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nss-tools-debuginfo-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"MozillaFirefox-60.5.0esr-109.58.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"MozillaFirefox-branding-SLE-60-32.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"MozillaFirefox-debuginfo-60.5.0esr-109.58.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"MozillaFirefox-debugsource-60.5.0esr-109.58.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"MozillaFirefox-translations-common-60.5.0esr-109.58.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libfreebl3-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libfreebl3-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libfreebl3-debuginfo-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libfreebl3-debuginfo-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libfreebl3-hmac-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libfreebl3-hmac-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsoftokn3-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsoftokn3-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsoftokn3-debuginfo-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsoftokn3-debuginfo-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsoftokn3-hmac-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsoftokn3-hmac-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"mozilla-nss-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"mozilla-nss-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"mozilla-nss-certs-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"mozilla-nss-certs-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"mozilla-nss-certs-debuginfo-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"mozilla-nss-certs-debuginfo-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"mozilla-nss-debuginfo-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"mozilla-nss-debuginfo-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"mozilla-nss-debugsource-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"mozilla-nss-sysinit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"mozilla-nss-sysinit-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"mozilla-nss-sysinit-debuginfo-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"mozilla-nss-tools-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"mozilla-nss-tools-debuginfo-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"MozillaFirefox-60.5.0esr-109.58.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"MozillaFirefox-branding-SLE-60-32.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"MozillaFirefox-debuginfo-60.5.0esr-109.58.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"MozillaFirefox-debugsource-60.5.0esr-109.58.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"MozillaFirefox-devel-60.5.0esr-109.58.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"MozillaFirefox-translations-common-60.5.0esr-109.58.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libfreebl3-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libfreebl3-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libfreebl3-debuginfo-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libfreebl3-debuginfo-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libfreebl3-hmac-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libfreebl3-hmac-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libsoftokn3-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libsoftokn3-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libsoftokn3-debuginfo-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libsoftokn3-debuginfo-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libsoftokn3-hmac-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libsoftokn3-hmac-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"mozilla-nss-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"mozilla-nss-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"mozilla-nss-certs-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"mozilla-nss-certs-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"mozilla-nss-certs-debuginfo-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"mozilla-nss-certs-debuginfo-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"mozilla-nss-debuginfo-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"mozilla-nss-debuginfo-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"mozilla-nss-debugsource-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"mozilla-nss-sysinit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"mozilla-nss-sysinit-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"mozilla-nss-sysinit-debuginfo-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"mozilla-nss-tools-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"mozilla-nss-tools-debuginfo-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"MozillaFirefox-60.5.0esr-109.58.3")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"MozillaFirefox-branding-SLE-60-32.5.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"MozillaFirefox-debuginfo-60.5.0esr-109.58.3")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"MozillaFirefox-debugsource-60.5.0esr-109.58.3")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"MozillaFirefox-translations-common-60.5.0esr-109.58.3")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libfreebl3-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libfreebl3-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libfreebl3-debuginfo-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libfreebl3-debuginfo-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libsoftokn3-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libsoftokn3-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libsoftokn3-debuginfo-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libsoftokn3-debuginfo-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"mozilla-nss-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"mozilla-nss-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"mozilla-nss-certs-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"mozilla-nss-certs-debuginfo-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"mozilla-nss-certs-debuginfo-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"mozilla-nss-debuginfo-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"mozilla-nss-debuginfo-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"mozilla-nss-debugsource-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"mozilla-nss-sysinit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"mozilla-nss-sysinit-debuginfo-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"mozilla-nss-tools-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"mozilla-nss-tools-debuginfo-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"MozillaFirefox-60.5.0esr-109.58.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"MozillaFirefox-branding-SLE-60-32.5.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"MozillaFirefox-debuginfo-60.5.0esr-109.58.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"MozillaFirefox-debugsource-60.5.0esr-109.58.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"MozillaFirefox-translations-common-60.5.0esr-109.58.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libfreebl3-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libfreebl3-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libfreebl3-debuginfo-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libfreebl3-debuginfo-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsoftokn3-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsoftokn3-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsoftokn3-debuginfo-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsoftokn3-debuginfo-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"mozilla-nss-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"mozilla-nss-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"mozilla-nss-certs-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"mozilla-nss-certs-debuginfo-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"mozilla-nss-certs-debuginfo-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"mozilla-nss-debuginfo-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"mozilla-nss-debuginfo-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"mozilla-nss-debugsource-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"mozilla-nss-sysinit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"mozilla-nss-sysinit-debuginfo-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"mozilla-nss-tools-3.41.1-58.25.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"mozilla-nss-tools-debuginfo-3.41.1-58.25.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaFirefox");
}
