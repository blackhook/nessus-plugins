#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101447);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id(
    "CVE-2017-3157"
  );

  script_name(english:"Virtuozzo 7 : autocorr-af / autocorr-bg / autocorr-ca / etc (VZLSA-2017-0914)");
  script_summary(english:"Checks the rpm output for the updated package.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Virtuozzo host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"An update for libreoffice is now available for Red Hat Enterprise
Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

LibreOffice is an open source, community-developed office productivity
suite. It includes key desktop applications, such as a word processor,
a spreadsheet, a presentation manager, a formula editor, and a drawing
program. LibreOffice replaces OpenOffice and provides a similar but
enhanced and extended office suite.

Security Fix(es) :

* It was found that LibreOffice disclosed contents of a file specified
in an embedded object's preview. An attacker could potentially use
this flaw to expose details of a system running LibreOffice as an
online service via a crafted document. (CVE-2017-3157)

Bug Fix(es) :

* Previously, an improper resource management caused the LibreOffice
Calc spreadsheet application to terminate unexpectedly after closing a
dialog window with accessibility support enabled. The resource
management has been improved, and the described problem no longer
occurs. (BZ#1425536)

* Previously, when an incorrect password was entered for a password
protected document, the document has been considered as valid and a
fallback attempt to open it as plain text has been made. As a
consequence, it could appear that the document succesfully loaded,
while just the encrypted unreadable content was shown. A fix has been
made to terminate import attempts after entering incorrect password,
and now nothing is loaded when a wrong password is entered.
(BZ#1426348)

* Previously, an improper resource management caused the LibreOffice
Calc spreadsheet application to terminate unexpectedly during exit,
after the Text Import dialog for CSV (Comma-separated Value) files
closed, when accessibility support was enabled. The resource
management has been improved, and the described problem no longer
occurs. (BZ#1425535)

Note that Tenable Network Security has attempted to extract the
preceding description block directly from the corresponding Red Hat
security advisory. Virtuozzo provides no description for VZLSA
advisories. Tenable has attempted to automatically clean and format
it as much as possible without introducing additional issues.");
  # http://repo.virtuozzo.com/vzlinux/announcements/json/VZLSA-2017-0914.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ff5c442b");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2017-0914");
  script_set_attribute(attribute:"solution", value:
"Update the affected autocorr-af / autocorr-bg / autocorr-ca / etc package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:autocorr-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:autocorr-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:autocorr-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:autocorr-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:autocorr-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:autocorr-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:autocorr-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:autocorr-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:autocorr-fa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:autocorr-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:autocorr-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:autocorr-ga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:autocorr-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:autocorr-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:autocorr-is");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:autocorr-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:autocorr-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:autocorr-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:autocorr-lb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:autocorr-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:autocorr-mn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:autocorr-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:autocorr-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:autocorr-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:autocorr-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:autocorr-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:autocorr-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:autocorr-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:autocorr-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:autocorr-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:autocorr-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:autocorr-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:autocorr-zh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-bsh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-calc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-draw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-emailmerge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-filters");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-gdb-debug-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-glade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-graphicfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-impress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-as");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-bn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-cy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-dz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-fa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-ga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-gu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-hi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-kk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-kn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-lv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-mai");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-ml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-mr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-nn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-nr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-nso");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-or");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-pa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-pt-BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-pt-PT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-si");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-ss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-st");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-ta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-te");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-th");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-tn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-ts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-ve");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-xh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-zh-Hans");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-zh-Hant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-langpack-zu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-librelogo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-nlpsolver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-officebean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-ogltrans");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-opensymbol-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-pdfimport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-pyuno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-rhino");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-sdk-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-ure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-wiki-publisher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreoffice-xsltfilter");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:virtuozzo:virtuozzo:7");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Virtuozzo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Virtuozzo/release", "Host/Virtuozzo/rpm-list");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/Virtuozzo/release");
if (isnull(release) || "Virtuozzo" >!< release) audit(AUDIT_OS_NOT, "Virtuozzo");
os_ver = pregmatch(pattern: "Virtuozzo Linux release ([0-9]+\.[0-9])(\D|$)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Virtuozzo");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Virtuozzo 7.x", "Virtuozzo " + os_ver);

if (!get_kb_item("Host/Virtuozzo/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Virtuozzo", cpu);

flag = 0;

pkgs = ["autocorr-af-5.0.6.2-5.vl7.1",
        "autocorr-bg-5.0.6.2-5.vl7.1",
        "autocorr-ca-5.0.6.2-5.vl7.1",
        "autocorr-cs-5.0.6.2-5.vl7.1",
        "autocorr-da-5.0.6.2-5.vl7.1",
        "autocorr-de-5.0.6.2-5.vl7.1",
        "autocorr-en-5.0.6.2-5.vl7.1",
        "autocorr-es-5.0.6.2-5.vl7.1",
        "autocorr-fa-5.0.6.2-5.vl7.1",
        "autocorr-fi-5.0.6.2-5.vl7.1",
        "autocorr-fr-5.0.6.2-5.vl7.1",
        "autocorr-ga-5.0.6.2-5.vl7.1",
        "autocorr-hr-5.0.6.2-5.vl7.1",
        "autocorr-hu-5.0.6.2-5.vl7.1",
        "autocorr-is-5.0.6.2-5.vl7.1",
        "autocorr-it-5.0.6.2-5.vl7.1",
        "autocorr-ja-5.0.6.2-5.vl7.1",
        "autocorr-ko-5.0.6.2-5.vl7.1",
        "autocorr-lb-5.0.6.2-5.vl7.1",
        "autocorr-lt-5.0.6.2-5.vl7.1",
        "autocorr-mn-5.0.6.2-5.vl7.1",
        "autocorr-nl-5.0.6.2-5.vl7.1",
        "autocorr-pl-5.0.6.2-5.vl7.1",
        "autocorr-pt-5.0.6.2-5.vl7.1",
        "autocorr-ro-5.0.6.2-5.vl7.1",
        "autocorr-ru-5.0.6.2-5.vl7.1",
        "autocorr-sk-5.0.6.2-5.vl7.1",
        "autocorr-sl-5.0.6.2-5.vl7.1",
        "autocorr-sr-5.0.6.2-5.vl7.1",
        "autocorr-sv-5.0.6.2-5.vl7.1",
        "autocorr-tr-5.0.6.2-5.vl7.1",
        "autocorr-vi-5.0.6.2-5.vl7.1",
        "autocorr-zh-5.0.6.2-5.vl7.1",
        "libreoffice-5.0.6.2-5.vl7.1",
        "libreoffice-base-5.0.6.2-5.vl7.1",
        "libreoffice-bsh-5.0.6.2-5.vl7.1",
        "libreoffice-calc-5.0.6.2-5.vl7.1",
        "libreoffice-core-5.0.6.2-5.vl7.1",
        "libreoffice-draw-5.0.6.2-5.vl7.1",
        "libreoffice-emailmerge-5.0.6.2-5.vl7.1",
        "libreoffice-filters-5.0.6.2-5.vl7.1",
        "libreoffice-gdb-debug-support-5.0.6.2-5.vl7.1",
        "libreoffice-glade-5.0.6.2-5.vl7.1",
        "libreoffice-graphicfilter-5.0.6.2-5.vl7.1",
        "libreoffice-impress-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-af-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-ar-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-as-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-bg-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-bn-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-br-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-ca-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-cs-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-cy-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-da-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-de-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-dz-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-el-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-en-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-es-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-et-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-eu-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-fa-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-fi-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-fr-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-ga-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-gl-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-gu-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-he-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-hi-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-hr-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-hu-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-it-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-ja-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-kk-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-kn-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-ko-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-lt-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-lv-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-mai-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-ml-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-mr-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-nb-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-nl-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-nn-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-nr-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-nso-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-or-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-pa-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-pl-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-pt-BR-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-pt-PT-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-ro-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-ru-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-si-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-sk-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-sl-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-sr-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-ss-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-st-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-sv-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-ta-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-te-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-th-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-tn-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-tr-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-ts-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-uk-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-ve-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-xh-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-zh-Hans-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-zh-Hant-5.0.6.2-5.vl7.1",
        "libreoffice-langpack-zu-5.0.6.2-5.vl7.1",
        "libreoffice-librelogo-5.0.6.2-5.vl7.1",
        "libreoffice-math-5.0.6.2-5.vl7.1",
        "libreoffice-nlpsolver-5.0.6.2-5.vl7.1",
        "libreoffice-officebean-5.0.6.2-5.vl7.1",
        "libreoffice-ogltrans-5.0.6.2-5.vl7.1",
        "libreoffice-opensymbol-fonts-5.0.6.2-5.vl7.1",
        "libreoffice-pdfimport-5.0.6.2-5.vl7.1",
        "libreoffice-postgresql-5.0.6.2-5.vl7.1",
        "libreoffice-pyuno-5.0.6.2-5.vl7.1",
        "libreoffice-rhino-5.0.6.2-5.vl7.1",
        "libreoffice-sdk-5.0.6.2-5.vl7.1",
        "libreoffice-sdk-doc-5.0.6.2-5.vl7.1",
        "libreoffice-ure-5.0.6.2-5.vl7.1",
        "libreoffice-wiki-publisher-5.0.6.2-5.vl7.1",
        "libreoffice-writer-5.0.6.2-5.vl7.1",
        "libreoffice-xsltfilter-5.0.6.2-5.vl7.1"];

foreach (pkg in pkgs)
  if (rpm_check(release:"Virtuozzo-7", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "autocorr-af / autocorr-bg / autocorr-ca / etc");
}
