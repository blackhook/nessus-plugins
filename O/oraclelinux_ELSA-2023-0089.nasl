#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2023-0089.
##

include('compat.inc');

if (description)
{
  script_id(170117);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id(
    "CVE-2022-3140",
    "CVE-2022-26305",
    "CVE-2022-26306",
    "CVE-2022-26307"
  );

  script_name(english:"Oracle Linux 8 : libreoffice (ELSA-2023-0089)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2023-0089 advisory.

  - LibreOffice supports the storage of passwords for web connections in the user's configuration database.
    The stored passwords are encrypted with a single master key provided by the user. A flaw in LibreOffice
    existed where master key was poorly encoded resulting in weakening its entropy from 128 to 43 bits making
    the stored passwords vulerable to a brute force attack if an attacker has access to the users stored
    config. This issue affects: The Document Foundation LibreOffice 7.2 versions prior to 7.2.7; 7.3 versions
    prior to 7.3.3. (CVE-2022-26307)

  - LibreOffice supports Office URI Schemes to enable browser integration of LibreOffice with MS SharePoint
    server. An additional scheme 'vnd.libreoffice.command' specific to LibreOffice was added. In the affected
    versions of LibreOffice links using that scheme could be constructed to call internal macros with
    arbitrary arguments. Which when clicked on, or activated by document events, could result in arbitrary
    script execution without warning. This issue affects: The Document Foundation LibreOffice 7.4 versions
    prior to 7.4.1; 7.3 versions prior to 7.3.6. (CVE-2022-3140)

  - An Improper Certificate Validation vulnerability in LibreOffice existed where determining if a macro was
    signed by a trusted author was done by only matching the serial number and issuer string of the used
    certificate with that of a trusted certificate. This is not sufficient to verify that the macro was
    actually signed with the certificate. An adversary could therefore create an arbitrary certificate with a
    serial number and an issuer string identical to a trusted certificate which LibreOffice would present as
    belonging to the trusted author, potentially leading to the user to execute arbitrary code contained in
    macros improperly trusted. This issue affects: The Document Foundation LibreOffice 7.2 versions prior to
    7.2.7; 7.3 versions prior to 7.3.1. (CVE-2022-26305)

  - LibreOffice supports the storage of passwords for web connections in the user's configuration database.
    The stored passwords are encrypted with a single master key provided by the user. A flaw in LibreOffice
    existed where the required initialization vector for encryption was always the same which weakens the
    security of the encryption making them vulnerable if an attacker has access to the user's configuration
    data. This issue affects: The Document Foundation LibreOffice 7.2 versions prior to 7.2.7; 7.3 versions
    prior to 7.3.1. (CVE-2022-26306)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2023-0089.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-26307");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-fa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-ga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-is");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-lb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-mn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-zh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-calc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-draw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-emailmerge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-filters");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-gdb-debug-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-graphicfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-help-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-help-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-help-bn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-help-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-help-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-help-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-help-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-help-dz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-help-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-help-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-help-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-help-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-help-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-help-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-help-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-help-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-help-gu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-help-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-help-hi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-help-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-help-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-help-id");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-help-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-help-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-help-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-help-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-help-lv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-help-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-help-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-help-nn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-help-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-help-pt-BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-help-pt-PT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-help-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-help-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-help-si");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-help-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-help-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-help-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-help-ta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-help-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-help-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-help-zh-Hans");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-help-zh-Hant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-impress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-as");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-bn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-cy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-dz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-fa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-ga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-gu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-hi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-id");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-kk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-kn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-lv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-mai");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-ml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-mr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-nn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-nr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-nso");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-or");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-pa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-pt-BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-pt-PT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-si");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-ss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-st");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-ta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-te");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-th");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-tn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-ts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-ve");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-xh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-zh-Hans");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-zh-Hant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-zu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-ogltrans");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-opensymbol-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-pdfimport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-pyuno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-sdk-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-ure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-ure-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-wiki-publisher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-xsltfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreofficekit");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_release = get_kb_item("Host/RedHat/release");
if (isnull(os_release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:os_release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'autocorr-af-6.4.7.2-12.0.1.el8_7', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-bg-6.4.7.2-12.0.1.el8_7', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-ca-6.4.7.2-12.0.1.el8_7', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-cs-6.4.7.2-12.0.1.el8_7', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-da-6.4.7.2-12.0.1.el8_7', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-de-6.4.7.2-12.0.1.el8_7', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-en-6.4.7.2-12.0.1.el8_7', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-es-6.4.7.2-12.0.1.el8_7', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-fa-6.4.7.2-12.0.1.el8_7', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-fi-6.4.7.2-12.0.1.el8_7', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-fr-6.4.7.2-12.0.1.el8_7', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-ga-6.4.7.2-12.0.1.el8_7', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-hr-6.4.7.2-12.0.1.el8_7', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-hu-6.4.7.2-12.0.1.el8_7', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-is-6.4.7.2-12.0.1.el8_7', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-it-6.4.7.2-12.0.1.el8_7', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-ja-6.4.7.2-12.0.1.el8_7', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-ko-6.4.7.2-12.0.1.el8_7', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-lb-6.4.7.2-12.0.1.el8_7', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-lt-6.4.7.2-12.0.1.el8_7', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-mn-6.4.7.2-12.0.1.el8_7', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-nl-6.4.7.2-12.0.1.el8_7', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-pl-6.4.7.2-12.0.1.el8_7', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-pt-6.4.7.2-12.0.1.el8_7', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-ro-6.4.7.2-12.0.1.el8_7', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-ru-6.4.7.2-12.0.1.el8_7', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-sk-6.4.7.2-12.0.1.el8_7', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-sl-6.4.7.2-12.0.1.el8_7', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-sr-6.4.7.2-12.0.1.el8_7', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-sv-6.4.7.2-12.0.1.el8_7', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-tr-6.4.7.2-12.0.1.el8_7', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-vi-6.4.7.2-12.0.1.el8_7', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autocorr-zh-6.4.7.2-12.0.1.el8_7', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-base-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-calc-6.4.7.2-12.0.1.el8_7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-calc-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-core-6.4.7.2-12.0.1.el8_7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-core-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-data-6.4.7.2-12.0.1.el8_7', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-draw-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-emailmerge-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-filters-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-gdb-debug-support-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-graphicfilter-6.4.7.2-12.0.1.el8_7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-graphicfilter-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-gtk3-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-help-ar-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-help-bg-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-help-bn-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-help-ca-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-help-cs-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-help-da-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-help-de-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-help-dz-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-help-el-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-help-en-6.4.7.2-12.0.1.el8_7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-help-en-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-help-es-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-help-et-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-help-eu-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-help-fi-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-help-fr-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-help-gl-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-help-gu-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-help-he-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-help-hi-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-help-hr-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-help-hu-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-help-id-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-help-it-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-help-ja-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-help-ko-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-help-lt-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-help-lv-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-help-nb-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-help-nl-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-help-nn-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-help-pl-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-help-pt-BR-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-help-pt-PT-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-help-ro-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-help-ru-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-help-si-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-help-sk-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-help-sl-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-help-sv-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-help-ta-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-help-tr-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-help-uk-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-help-zh-Hans-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-help-zh-Hant-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-impress-6.4.7.2-12.0.1.el8_7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-impress-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-af-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-ar-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-as-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-bg-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-bn-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-br-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-ca-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-cs-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-cy-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-da-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-de-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-dz-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-el-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-en-6.4.7.2-12.0.1.el8_7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-en-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-es-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-et-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-eu-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-fa-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-fi-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-fr-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-ga-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-gl-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-gu-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-he-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-hi-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-hr-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-hu-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-id-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-it-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-ja-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-kk-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-kn-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-ko-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-lt-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-lv-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-mai-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-ml-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-mr-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-nb-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-nl-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-nn-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-nr-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-nso-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-or-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-pa-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-pl-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-pt-BR-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-pt-PT-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-ro-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-ru-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-si-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-sk-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-sl-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-sr-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-ss-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-st-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-sv-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-ta-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-te-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-th-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-tn-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-tr-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-ts-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-uk-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-ve-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-xh-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-zh-Hans-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-zh-Hant-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-langpack-zu-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-math-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-ogltrans-6.4.7.2-12.0.1.el8_7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-ogltrans-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-opensymbol-fonts-6.4.7.2-12.0.1.el8_7', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-pdfimport-6.4.7.2-12.0.1.el8_7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-pdfimport-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-pyuno-6.4.7.2-12.0.1.el8_7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-pyuno-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-sdk-6.4.7.2-12.0.1.el8_7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-sdk-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-sdk-doc-6.4.7.2-12.0.1.el8_7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-sdk-doc-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-ure-6.4.7.2-12.0.1.el8_7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-ure-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-ure-common-6.4.7.2-12.0.1.el8_7', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-wiki-publisher-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-writer-6.4.7.2-12.0.1.el8_7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-writer-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-x11-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-xsltfilter-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreofficekit-6.4.7.2-12.0.1.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release) {
    if (exists_check) {
        if (rpm_exists(release:_release, rpm:exists_check) && rpm_check(release:_release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'autocorr-af / autocorr-bg / autocorr-ca / etc');
}
