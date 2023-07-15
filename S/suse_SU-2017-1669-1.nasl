#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:1669-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101055);
  script_version("3.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2016-10196", "CVE-2017-5429", "CVE-2017-5430", "CVE-2017-5432", "CVE-2017-5433", "CVE-2017-5434", "CVE-2017-5435", "CVE-2017-5436", "CVE-2017-5438", "CVE-2017-5439", "CVE-2017-5440", "CVE-2017-5441", "CVE-2017-5442", "CVE-2017-5443", "CVE-2017-5444", "CVE-2017-5445", "CVE-2017-5446", "CVE-2017-5447", "CVE-2017-5448", "CVE-2017-5449", "CVE-2017-5451", "CVE-2017-5454", "CVE-2017-5455", "CVE-2017-5456", "CVE-2017-5459", "CVE-2017-5460", "CVE-2017-5461", "CVE-2017-5462", "CVE-2017-5464", "CVE-2017-5465", "CVE-2017-5466", "CVE-2017-5467", "CVE-2017-5469", "CVE-2017-5470", "CVE-2017-5472", "CVE-2017-7749", "CVE-2017-7750", "CVE-2017-7751", "CVE-2017-7752", "CVE-2017-7754", "CVE-2017-7755", "CVE-2017-7756", "CVE-2017-7757", "CVE-2017-7758", "CVE-2017-7761", "CVE-2017-7763", "CVE-2017-7764", "CVE-2017-7765", "CVE-2017-7768", "CVE-2017-7778");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : MozillaFirefox, MozillaFirefox-branding-SLE (SUSE-SU-2017:1669-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Mozilla Firefox was updated to the new ESR 52.2 release, which
fixes the following issues (bsc#1043960) :

  - MFSA 2017-16/CVE-2017-7758 Out-of-bounds read in Opus
    encoder

  - MFSA 2017-16/CVE-2017-7749 Use-after-free during
    docshell reloading

  - MFSA 2017-16/CVE-2017-7751 Use-after-free with content
    viewer listeners

  - MFSA 2017-16/CVE-2017-5472 Use-after-free using
    destroyed node when regenerating trees

  - MFSA 2017-16/CVE-2017-5470 Memory safety bugs fixed in
    Firefox 54 and Firefox ESR 52.2

  - MFSA 2017-16/CVE-2017-7752 Use-after-free with IME input

  - MFSA 2017-16/CVE-2017-7750 Use-after-free with track
    elements

  - MFSA 2017-16/CVE-2017-7768 32 byte arbitrary file read
    through Mozilla Maintenance Service

  - MFSA 2017-16/CVE-2017-7778 Vulnerabilities in the
    Graphite 2 library

  - MFSA 2017-16/CVE-2017-7754 Out-of-bounds read in WebGL
    with ImageInfo object

  - MFSA 2017-16/CVE-2017-7755 Privilege escalation through
    Firefox Installer with same directory DLL files

  - MFSA 2017-16/CVE-2017-7756 Use-after-free and
    use-after-scope logging XHR header errors

  - MFSA 2017-16/CVE-2017-7757 Use-after-free in IndexedDB

  - MFSA 2017-16/CVE-2017-7761 File deletion and privilege
    escalation through Mozilla Maintenance Service
    helper.exe application

  - MFSA 2017-16/CVE-2017-7763 Mac fonts render some unicode
    characters as spaces

  - MFSA 2017-16/CVE-2017-7765 Mark of the Web bypass when
    saving executable files

  - MFSA 2017-16/CVE-2017-7764 (bmo#1364283,
    bmo#http://www.unicode.org/reports/tr31/tr31-26
    .html#Aspirational_Use_Scripts) Domain spoofing with
    combination of Canadian Syllabics and other unicode
    blocks

  - update to Firefox ESR 52.1 (bsc#1035082)

  - MFSA 2017-12/CVE-2016-10196 Vulnerabilities in Libevent
    library

  - MFSA 2017-12/CVE-2017-5443 Out-of-bounds write during
    BinHex decoding

  - MFSA 2017-12/CVE-2017-5429 Memory safety bugs fixed in
    Firefox 53, Firefox ESR 45.9, and Firefox ESR 52.1

  - MFSA 2017-12/CVE-2017-5464 Memory corruption with
    accessibility and DOM manipulation

  - MFSA 2017-12/CVE-2017-5465 Out-of-bounds read in
    ConvolvePixel

  - MFSA 2017-12/CVE-2017-5466 Origin confusion when
    reloading isolated data:text/html URL

  - MFSA 2017-12/CVE-2017-5467 Memory corruption when
    drawing Skia content

  - MFSA 2017-12/CVE-2017-5460 Use-after-free in frame
    selection

  - MFSA 2017-12/CVE-2017-5461 Out-of-bounds write in Base64
    encoding in NSS

  - MFSA 2017-12/CVE-2017-5448 Out-of-bounds write in
    ClearKeyDecryptor

  - MFSA 2017-12/CVE-2017-5449 Crash during bidirectional
    unicode manipulation with animation

  - MFSA 2017-12/CVE-2017-5446 Out-of-bounds read when
    HTTP/2 DATA frames are sent with incorrect data

  - MFSA 2017-12/CVE-2017-5447 Out-of-bounds read during
    glyph processing

  - MFSA 2017-12/CVE-2017-5444 Buffer overflow while parsing
    application/http-index-format content

  - MFSA 2017-12/CVE-2017-5445 Uninitialized values used
    while parsing application/http- index-format content

  - MFSA 2017-12/CVE-2017-5442 Use-after-free during style
    changes

  - MFSA 2017-12/CVE-2017-5469 Potential Buffer overflow in
    flex-generated code

  - MFSA 2017-12/CVE-2017-5440 Use-after-free in
    txExecutionState destructor during XSLT processing

  - MFSA 2017-12/CVE-2017-5441 Use-after-free with selection
    during scroll events

  - MFSA 2017-12/CVE-2017-5439 Use-after-free in nsTArray
    Length() during XSLT processing

  - MFSA 2017-12/CVE-2017-5438 Use-after-free in nsAutoPtr
    during XSLT processing

  - MFSA 2017-12/CVE-2017-5436 Out-of-bounds write with
    malicious font in Graphite 2

  - MFSA 2017-12/CVE-2017-5435 Use-after-free during
    transaction processing in the editor

  - MFSA 2017-12/CVE-2017-5434 Use-after-free during focus
    handling

  - MFSA 2017-12/CVE-2017-5433 Use-after-free in SMIL
    animation functions

  - MFSA 2017-12/CVE-2017-5432 Use-after-free in text input
    selection

  - MFSA 2017-12/CVE-2017-5430 Memory safety bugs fixed in
    Firefox 53 and Firefox ESR 52.1

  - MFSA 2017-12/CVE-2017-5459 Buffer overflow in WebGL

  - MFSA 2017-12/CVE-2017-5462 DRBG flaw in NSS

  - MFSA 2017-12/CVE-2017-5455 Sandbox escape through
    internal feed reader APIs

  - MFSA 2017-12/CVE-2017-5454 Sandbox escape allowing file
    system read access through file picker

  - MFSA 2017-12/CVE-2017-5456 Sandbox escape allowing local
    file system access

  - MFSA 2017-12/CVE-2017-5451 Addressbar spoofing with
    onblur event

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.unicode.org/reports/tr31/tr31-26"
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
  # https://www.suse.com/support/update/announcement/2017/suse-su-20171669-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6c4e839e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud 6:zypper in -t patch
SUSE-OpenStack-Cloud-6-2017-1035=1

SUSE Linux Enterprise Software Development Kit 12-SP2:zypper in -t
patch SUSE-SLE-SDK-12-SP2-2017-1035=1

SUSE Linux Enterprise Server for SAP 12-SP1:zypper in -t patch
SUSE-SLE-SAP-12-SP1-2017-1035=1

SUSE Linux Enterprise Server for SAP 12:zypper in -t patch
SUSE-SLE-SAP-12-2017-1035=1

SUSE Linux Enterprise Server for Raspberry Pi 12-SP2:zypper in -t
patch SUSE-SLE-RPI-12-SP2-2017-1035=1

SUSE Linux Enterprise Server 12-SP2:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2017-1035=1

SUSE Linux Enterprise Server 12-SP1-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2017-1035=1

SUSE Linux Enterprise Server 12-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-2017-1035=1

SUSE Linux Enterprise Desktop 12-SP2:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP2-2017-1035=1

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-branding-SLE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/27");
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
if (os_ver == "SLES12" && (! preg(pattern:"^(0|1|2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0/1/2", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", reference:"MozillaFirefox-52.2.0esr-108.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"MozillaFirefox-branding-SLE-52-31.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"MozillaFirefox-debuginfo-52.2.0esr-108.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"MozillaFirefox-debugsource-52.2.0esr-108.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"MozillaFirefox-devel-52.2.0esr-108.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"MozillaFirefox-translations-52.2.0esr-108.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"MozillaFirefox-52.2.0esr-108.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"MozillaFirefox-branding-SLE-52-31.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"MozillaFirefox-debuginfo-52.2.0esr-108.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"MozillaFirefox-debugsource-52.2.0esr-108.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"MozillaFirefox-devel-52.2.0esr-108.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"MozillaFirefox-translations-52.2.0esr-108.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"MozillaFirefox-52.2.0esr-108.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"MozillaFirefox-branding-SLE-52-31.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"MozillaFirefox-debuginfo-52.2.0esr-108.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"MozillaFirefox-debugsource-52.2.0esr-108.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"MozillaFirefox-translations-52.2.0esr-108.3")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"MozillaFirefox-52.2.0esr-108.3")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"MozillaFirefox-branding-SLE-52-31.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"MozillaFirefox-debuginfo-52.2.0esr-108.3")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"MozillaFirefox-debugsource-52.2.0esr-108.3")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"MozillaFirefox-translations-52.2.0esr-108.3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaFirefox / MozillaFirefox-branding-SLE");
}
