#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:2872-2.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104542);
  script_version("3.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-7793", "CVE-2017-7805", "CVE-2017-7810", "CVE-2017-7814", "CVE-2017-7818", "CVE-2017-7819", "CVE-2017-7823", "CVE-2017-7824", "CVE-2017-7825");

  script_name(english:"SUSE SLES11 Security Update : MozillaFirefox, mozilla-nss (SUSE-SU-2017:2872-2)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for MozillaFirefox and mozilla-nss fixes the following
issues: Mozilla Firefox was updated to ESR 52.4 (bsc#1060445)

  - MFSA 2017-22/CVE-2017-7825: OS X fonts render some
    Tibetan and Arabic unicode characters as spaces

  - MFSA 2017-22/CVE-2017-7805: Use-after-free in TLS 1.2
    generating handshake hashes

  - MFSA 2017-22/CVE-2017-7819: Use-after-free while
    resizing images in design mode

  - MFSA 2017-22/CVE-2017-7818: Use-after-free during ARIA
    array manipulation

  - MFSA 2017-22/CVE-2017-7793: Use-after-free with Fetch
    API

  - MFSA 2017-22/CVE-2017-7824: Buffer overflow when drawing
    and validating elements with ANGLE

  - MFSA 2017-22/CVE-2017-7810: Memory safety bugs fixed in
    Firefox 56 and Firefox ESR 52.4

  - MFSA 2017-22/CVE-2017-7823: CSP sandbox directive did
    not create a unique origin

  - MFSA 2017-22/CVE-2017-7814: Blob and data URLs bypass
    phishing and malware protection warnings Mozilla Network
    Security Services (Mozilla NSS) received a security 
fix :

  - MFSA 2017-22/CVE-2017-7805: Use-after-free in TLS 1.2
    generating handshake hashes (bsc#1061005, bsc#1060445)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1060445"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1061005"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7793/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7805/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7810/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7814/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7818/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7819/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7823/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7824/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7825/"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20172872-2/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7bf725b4"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11-SP4:zypper in -t
patch sdksp4-firefox-201710-13330=1

SUSE Linux Enterprise Server 11-SP4:zypper in -t patch
slessp4-firefox-201710-13330=1

SUSE Linux Enterprise Server 11-SP3-LTSS:zypper in -t patch
slessp3-firefox-201710-13330=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfreebl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsoftokn3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/14");
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
if (! preg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "s390x|x86_64") audit(AUDIT_ARCH_NOT, "s390x / x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! preg(pattern:"^(3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP3/4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"MozillaFirefox-52.4.0esr-72.13.2")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"MozillaFirefox-translations-52.4.0esr-72.13.2")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"libfreebl3-3.29.5-47.6.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"libfreebl3-32bit-3.29.5-47.6.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"libsoftokn3-3.29.5-47.6.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"libsoftokn3-32bit-3.29.5-47.6.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"mozilla-nss-3.29.5-47.6.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"mozilla-nss-32bit-3.29.5-47.6.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"mozilla-nss-tools-3.29.5-47.6.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"MozillaFirefox-52.4.0esr-72.13.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"MozillaFirefox-translations-52.4.0esr-72.13.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"libfreebl3-3.29.5-47.6.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"libfreebl3-32bit-3.29.5-47.6.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"libsoftokn3-3.29.5-47.6.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"libsoftokn3-32bit-3.29.5-47.6.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"mozilla-nss-3.29.5-47.6.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"mozilla-nss-32bit-3.29.5-47.6.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"mozilla-nss-tools-3.29.5-47.6.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaFirefox / mozilla-nss");
}
