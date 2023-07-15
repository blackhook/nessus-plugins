#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:2235-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102694);
  script_version("3.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2015-5276", "CVE-2016-10196", "CVE-2017-5429", "CVE-2017-5430", "CVE-2017-5432", "CVE-2017-5433", "CVE-2017-5434", "CVE-2017-5435", "CVE-2017-5436", "CVE-2017-5438", "CVE-2017-5439", "CVE-2017-5440", "CVE-2017-5441", "CVE-2017-5442", "CVE-2017-5443", "CVE-2017-5444", "CVE-2017-5445", "CVE-2017-5446", "CVE-2017-5447", "CVE-2017-5448", "CVE-2017-5449", "CVE-2017-5451", "CVE-2017-5454", "CVE-2017-5455", "CVE-2017-5456", "CVE-2017-5459", "CVE-2017-5460", "CVE-2017-5461", "CVE-2017-5462", "CVE-2017-5464", "CVE-2017-5465", "CVE-2017-5466", "CVE-2017-5467", "CVE-2017-5469", "CVE-2017-5470", "CVE-2017-5472", "CVE-2017-7749", "CVE-2017-7750", "CVE-2017-7751", "CVE-2017-7752", "CVE-2017-7754", "CVE-2017-7755", "CVE-2017-7756", "CVE-2017-7757", "CVE-2017-7758", "CVE-2017-7761", "CVE-2017-7763", "CVE-2017-7764", "CVE-2017-7765", "CVE-2017-7768", "CVE-2017-7778");

  script_name(english:"SUSE SLES11 Security Update : MozillaFirefox, MozillaFirefox-branding-SLED, firefox-gcc5, mozilla-nss (SUSE-SU-2017:2235-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for MozillaFirefox and mozilla-nss fixes the following
issues: Security issues fixed :

  - Fixes in Firefox ESR 52.2 (bsc#1043960,MFSA 2017-16)

  - CVE-2017-7758: Out-of-bounds read in Opus encoder

  - CVE-2017-7749: Use-after-free during docshell reloading

  - CVE-2017-7751: Use-after-free with content viewer
    listeners

  - CVE-2017-5472: Use-after-free using destroyed node when
    regenerating trees

  - CVE-2017-5470: Memory safety bugs fixed in Firefox 54
    and Firefox ESR 52.2

  - CVE-2017-7752: Use-after-free with IME input

  - CVE-2017-7750: Use-after-free with track elements

  - CVE-2017-7768: 32 byte arbitrary file read through
    Mozilla Maintenance Service

  - CVE-2017-7778: Vulnerabilities in the Graphite 2 library

  - CVE-2017-7754: Out-of-bounds read in WebGL with
    ImageInfo object

  - CVE-2017-7755: Privilege escalation through Firefox
    Installer with same directory DLL files

  - CVE-2017-7756: Use-after-free and use-after-scope
    logging XHR header errors

  - CVE-2017-7757: Use-after-free in IndexedDB

  - CVE-2017-7761: File deletion and privilege escalation
    through Mozilla Maintenance Service helper.exe
    application

  - CVE-2017-7763: Mac fonts render some unicode characters
    as spaces

  - CVE-2017-7765: Mark of the Web bypass when saving
    executable files

  - CVE-2017-7764: Domain spoofing with combination of
    Canadian Syllabics and other unicode blocks

  - update to Firefox ESR 52.1 (bsc#1035082,MFSA 2017-12)

  - CVE-2016-10196: Vulnerabilities in Libevent library

  - CVE-2017-5443: Out-of-bounds write during BinHex
    decoding

  - CVE-2017-5429: Memory safety bugs fixed in Firefox 53,
    Firefox ESR 45.9, and Firefox ESR 52.1

  - CVE-2017-5464: Memory corruption with accessibility and
    DOM manipulation

  - CVE-2017-5465: Out-of-bounds read in ConvolvePixel

  - CVE-2017-5466: Origin confusion when reloading isolated
    data:text/html URL

  - CVE-2017-5467: Memory corruption when drawing Skia
    content

  - CVE-2017-5460: Use-after-free in frame selection

  - CVE-2017-5461: Out-of-bounds write in Base64 encoding in
    NSS

  - CVE-2017-5448: Out-of-bounds write in ClearKeyDecryptor

  - CVE-2017-5449: Crash during bidirectional unicode
    manipulation with animation

  - CVE-2017-5446: Out-of-bounds read when HTTP/2 DATA
    frames are sent with incorrect data

  - CVE-2017-5447: Out-of-bounds read during glyph
    processing

  - CVE-2017-5444: Buffer overflow while parsing
    application/http-index-format content

  - CVE-2017-5445: Uninitialized values used while parsing
    application/http- index-format content

  - CVE-2017-5442: Use-after-free during style changes

  - CVE-2017-5469: Potential Buffer overflow in
    flex-generated code

  - CVE-2017-5440: Use-after-free in txExecutionState
    destructor during XSLT processing

  - CVE-2017-5441: Use-after-free with selection during
    scroll events

  - CVE-2017-5439: Use-after-free in nsTArray Length()
    during XSLT processing

  - CVE-2017-5438: Use-after-free in nsAutoPtr during XSLT
    processing

  - CVE-2017-5436: Out-of-bounds write with malicious font
    in Graphite 2

  - CVE-2017-5435: Use-after-free during transaction
    processing in the editor

  - CVE-2017-5434: Use-after-free during focus handling

  - CVE-2017-5433: Use-after-free in SMIL animation
    functions

  - CVE-2017-5432: Use-after-free in text input selection

  - CVE-2017-5430: Memory safety bugs fixed in Firefox 53
    and Firefox ESR 52.1

  - CVE-2017-5459: Buffer overflow in WebGL

  - CVE-2017-5462: DRBG flaw in NSS

  - CVE-2017-5455: Sandbox escape through internal feed
    reader APIs

  - CVE-2017-5454: Sandbox escape allowing file system read
    access through file picker

  - CVE-2017-5456: Sandbox escape allowing local file system
    access

  - CVE-2017-5451: Addressbar spoofing with onblur event

  - General

  - CVE-2015-5276: Fix for C++11 std::random_device short
    reads (bsc#945842) Bugfixes :

  - workaround for Firefox hangs (bsc#1031485, bsc#1025108)

  - Update to gcc-5-branch head.

  - Includes fixes for (bsc#966220), (bsc#962765),
    (bsc#964468), (bsc#939460), (bsc#930496), (bsc#930392)
    and (bsc#955382).

  - Add fix to revert accidential libffi ABI breakage on
    AARCH64. (bsc#968771)

  - Build s390[x] with --with-tune=z9-109 --with-arch=z900
    on SLE11 again. (bsc#954002)

  - Fix libffi include install. (bsc#935510)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1025108"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1031485"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1035082"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1043960"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=930392"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=930496"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=935510"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=939460"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=945842"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=953831"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=954002"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=955382"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=962765"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=964468"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=966220"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=968771"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5276/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-10196/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5429/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5430/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5432/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5433/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5434/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5435/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5436/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5438/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5439/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5440/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5441/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5442/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5443/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5444/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5445/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5446/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5447/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5448/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5449/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5451/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5454/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5455/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5456/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5459/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5460/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5461/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5462/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5464/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5465/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5466/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5467/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5469/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5470/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5472/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7749/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7750/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7751/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7752/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7754/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7755/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7756/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7757/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7758/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7761/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7763/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7764/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7765/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7768/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7778/"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20172235-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?08740681"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11-SP4:zypper in -t
patch sdksp4-MozillaFirefox-13237=1

SUSE Linux Enterprise Server 11-SP4:zypper in -t patch
slessp4-MozillaFirefox-13237=1

SUSE Linux Enterprise Server 11-SP3-LTSS:zypper in -t patch
slessp3-MozillaFirefox-13237=1

SUSE Linux Enterprise Point of Sale 11-SP3:zypper in -t patch
sleposp3-MozillaFirefox-13237=1

SUSE Linux Enterprise Debuginfo 11-SP4:zypper in -t patch
dbgsp4-MozillaFirefox-13237=1

SUSE Linux Enterprise Debuginfo 11-SP3:zypper in -t patch
dbgsp3-MozillaFirefox-13237=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-branding-SLED");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox-libffi4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox-libstdc++6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfreebl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsoftokn3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/23");
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

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! preg(pattern:"^(3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP3/4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"libfreebl3-32bit-3.29.5-47.3.2")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"libsoftokn3-32bit-3.29.5-47.3.2")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"mozilla-nss-32bit-3.29.5-47.3.2")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"libfreebl3-32bit-3.29.5-47.3.2")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"libsoftokn3-32bit-3.29.5-47.3.2")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"mozilla-nss-32bit-3.29.5-47.3.2")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"firefox-libffi4-5.3.1+r233831-7.1", allowmaj:TRUE)) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"firefox-libstdc++6-5.3.1+r233831-7.1", allowmaj:TRUE)) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libfreebl3-3.29.5-47.3.2")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libsoftokn3-3.29.5-47.3.2")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"mozilla-nss-3.29.5-47.3.2")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"mozilla-nss-tools-3.29.5-47.3.2")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"MozillaFirefox-52.2.0esr-72.5.2")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"MozillaFirefox-branding-SLED-52-24.3.44")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"MozillaFirefox-translations-52.2.0esr-72.5.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"libfreebl3-32bit-3.29.5-47.3.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"libsoftokn3-32bit-3.29.5-47.3.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"mozilla-nss-32bit-3.29.5-47.3.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"libfreebl3-32bit-3.29.5-47.3.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"libsoftokn3-32bit-3.29.5-47.3.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"mozilla-nss-32bit-3.29.5-47.3.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"MozillaFirefox-52.2.0esr-72.5.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"MozillaFirefox-branding-SLED-52-24.3.44")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"MozillaFirefox-translations-52.2.0esr-72.5.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"firefox-libffi4-5.3.1+r233831-7.1", allowmaj:TRUE)) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"firefox-libstdc++6-5.3.1+r233831-7.1", allowmaj:TRUE)) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"libfreebl3-3.29.5-47.3.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"libsoftokn3-3.29.5-47.3.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"mozilla-nss-3.29.5-47.3.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"mozilla-nss-tools-3.29.5-47.3.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaFirefox / MozillaFirefox-branding-SLED / firefox-gcc5 / mozilla-nss");
}
