#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:3683-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(120160);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2018-10583");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : libepubgen, liblangtag, libmwaw, libnumbertext, libreoffice, libstaroffice, libwps, myspell-dictionaries, xmlsec1 (SUSE-SU-2018:3683-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for LibreOffice, libepubgen, liblangtag, libmwaw,
libnumbertext, libstaroffice, libwps, myspell-dictionaries, xmlsec1
fixes the following issues :

LibreOffice was updated to 6.1.3.2 (fate#326624) and contains new
features and lots of bugfixes :

The full changelog can be found on :

https://wiki.documentfoundation.org/ReleaseNotes/6.1

Bugfixes :

bsc#1095639 Exporting to PPTX results in vertical labels being shown
horizontally

bsc#1098891 Table in PPTX misplaced and partly blue

bsc#1088263 Labels in chart change (from white and other colors) to
black when saving as PPTX

bsc#1095601 Exporting to PPTX shifts arrow shapes quite a bit

Add more translations :

  - Belarusian

  - Bodo

  - Dogri

  - Frisian

  - Gaelic

  - Paraguayan_Guaran

  - Upper_Sorbian

  - Konkani

  - Kashmiri

  - Luxembourgish

  - Monglolian

  - Manipuri

  - Burnese

  - Occitan

  - Kinyarwanda

  - Santali

  - Sanskrit

  - Sindhi

  - Sidamo

  - Tatar

  - Uzbek

  - Upper Sorbian

  - Venetian

  - Amharic

  - Asturian

  - Tibetian

  - Bosnian

  - English GB

  - English ZA

  - Indonesian

  - Icelandic

  - Georgian

  - Khmer

  - Lao

  - Macedonian

  - Nepali

  - Oromo

  - Albanian

  - Tajik

  - Uyghur

  - Vietnamese

  - Kurdish

Try to build all languages see bsc#1096360

Make sure to install the KDE5/Qt5 UI/filepicker

Try to implement safeguarding to avoid bsc#1050305

Disable base-drivers-mysql as it needs mysqlcppcon that is only for
mysql and not mariadb, causes issues bsc#1094779

  - Users can still connect using jdbc/odbc

Fix java detection on machines with too many cpus

CVE-2018-10583: An information disclosure vulnerability occured when
LibreOffice automatically processed and initiated an SMB connection
embedded in a malicious file, as demonstrated by
xlink:href=file://192.168.0.2/test.jpg within an
office:document-content element in a .odt XML document. (bsc#1091606)

libepubgen was updated to 0.1.1: Avoid <div> inside or <span>.Avoid
writin vertical-align attribute without a value.

Fix generation of invalid XHTML when there is a link starting at the
beginning of a footnote.

Handle relative width for images.

Fixed layout: write chapter names to improve navigation.

Support writing mode.

Start a new HTML file at every page span in addition to the splits
induced by the chosen split method. This is to ensure that specified
writing mode works correctly, as it is HTML attribute.

liblangtag was updated to 0.6.2: use standard function

fix leak in test

libmwaw was updated to 0.3.14: Support MS Multiplan 1.1 files

libnumbertext was update to 1.0.5: Various fixes in numerical
calculations and issues reported on libreoffice tracker

libstaroffice was updated to 0.0.6: retrieve some StarMath's formula,

retrieve some charts as graphic,

retrieve some fields in sda/sdc/sdp text-boxes,

.sdw: retrieve more attachments.

libwps was updated to 0.4.9: QuattroPro: add parser to .wb3 files

Multiplan: add parser to DOS v1-v3 files

charts: try to retrieve charts in .wk*, .wq* files

QuattroPro: add parser to .wb[12] files

myspell-dictionaries was updated to 20181025: Turkish dictionary added

Updated French dictionary

xmlsec1 was updated to 1.2.26: Added xmlsec-mscng module based on
Microsoft Cryptography API: Next Generation

Added support for GOST 2012 and fixed CryptoPro CSP provider for GOST
R 34.10-2001 in xmlsec-mscrypto

</span>

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1050305"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1088263"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1091606"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1094779"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1095601"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1095639"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1096360"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1098891"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1104876"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://wiki.documentfoundation.org/ReleaseNotes/6.1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-10583/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20183683-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b9eb9364"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 15:zypper in -t patch
SUSE-SLE-Product-WE-15-2018-2616=1

SUSE Linux Enterprise Module for Packagehub Subpackages 15:zypper in
-t patch SUSE-SLE-Module-Packagehub-Subpackages-15-2018-2616=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-2018-2616=1

SUSE Linux Enterprise Module for Basesystem 15:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-2018-2616=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmwaw-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmwaw-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmwaw-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmwaw-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmwaw-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libstaroffice-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libstaroffice-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libstaroffice-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libstaroffice-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libstaroffice-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwps-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwps-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwps-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwps-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libxmlsec1-gcrypt1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libxmlsec1-gcrypt1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libxmlsec1-gnutls1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libxmlsec1-gnutls1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libxmlsec1-openssl1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libxmlsec1-openssl1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-dictionaries");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-lightproof-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-lightproof-hu_HU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-lightproof-pt_BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-lightproof-ru_RU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xmlsec1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xmlsec1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xmlsec1-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xmlsec1-gcrypt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xmlsec1-gnutls-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xmlsec1-openssl-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/02");
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
if (rpm_check(release:"SLES15", sp:"0", reference:"libmwaw-debuginfo-0.3.14-4.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libmwaw-debugsource-0.3.14-4.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libmwaw-devel-0.3.14-4.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libmwaw-tools-0.3.14-4.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libmwaw-tools-debuginfo-0.3.14-4.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libstaroffice-debuginfo-0.0.6-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libstaroffice-debugsource-0.0.6-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libstaroffice-devel-0.0.6-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libstaroffice-tools-0.0.6-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libstaroffice-tools-debuginfo-0.0.6-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libwps-debuginfo-0.4.9-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libwps-debugsource-0.4.9-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libwps-tools-0.4.9-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libwps-tools-debuginfo-0.4.9-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libxmlsec1-gcrypt1-1.2.26-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libxmlsec1-gcrypt1-debuginfo-1.2.26-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libxmlsec1-gnutls1-1.2.26-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libxmlsec1-gnutls1-debuginfo-1.2.26-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libxmlsec1-openssl1-1.2.26-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libxmlsec1-openssl1-debuginfo-1.2.26-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"myspell-dictionaries-20181025-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"myspell-lightproof-en-20181025-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"myspell-lightproof-hu_HU-20181025-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"myspell-lightproof-pt_BR-20181025-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"myspell-lightproof-ru_RU-20181025-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"xmlsec1-1.2.26-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"xmlsec1-debuginfo-1.2.26-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"xmlsec1-debugsource-1.2.26-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"xmlsec1-gcrypt-devel-1.2.26-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"xmlsec1-gnutls-devel-1.2.26-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"xmlsec1-openssl-devel-1.2.26-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libmwaw-debuginfo-0.3.14-4.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libmwaw-debugsource-0.3.14-4.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libmwaw-devel-0.3.14-4.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libmwaw-tools-0.3.14-4.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libmwaw-tools-debuginfo-0.3.14-4.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libstaroffice-debuginfo-0.0.6-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libstaroffice-debugsource-0.0.6-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libstaroffice-devel-0.0.6-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libstaroffice-tools-0.0.6-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libstaroffice-tools-debuginfo-0.0.6-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libwps-debuginfo-0.4.9-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libwps-debugsource-0.4.9-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libwps-tools-0.4.9-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libwps-tools-debuginfo-0.4.9-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libxmlsec1-gcrypt1-1.2.26-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libxmlsec1-gcrypt1-debuginfo-1.2.26-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libxmlsec1-gnutls1-1.2.26-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libxmlsec1-gnutls1-debuginfo-1.2.26-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libxmlsec1-openssl1-1.2.26-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libxmlsec1-openssl1-debuginfo-1.2.26-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"myspell-dictionaries-20181025-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"myspell-lightproof-en-20181025-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"myspell-lightproof-hu_HU-20181025-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"myspell-lightproof-pt_BR-20181025-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"myspell-lightproof-ru_RU-20181025-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"xmlsec1-1.2.26-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"xmlsec1-debuginfo-1.2.26-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"xmlsec1-debugsource-1.2.26-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"xmlsec1-gcrypt-devel-1.2.26-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"xmlsec1-gnutls-devel-1.2.26-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"xmlsec1-openssl-devel-1.2.26-3.3.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libepubgen / liblangtag / libmwaw / libnumbertext / libreoffice / libstaroffice / libwps / myspell-dictionaries / xmlsec1");
}
