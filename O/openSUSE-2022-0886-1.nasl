#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2022:0886-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159056);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/18");

  script_cve_id("CVE-2021-25636");

  script_name(english:"openSUSE 15 Security Update : libreoffice (openSUSE-SU-2022:0886-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by a vulnerability as referenced in the
openSUSE-SU-2022:0886-1 advisory.

  - LibreOffice supports digital signatures of ODF documents and macros within documents, presenting visual
    aids that no alteration of the document occurred since the last signing and that the signature is valid.
    An Improper Certificate Validation vulnerability in LibreOffice allowed an attacker to create a digitally
    signed ODF document, by manipulating the documentsignatures.xml or macrosignatures.xml stream within the
    document to contain both X509Data and KeyValue children of the KeyInfo tag, which when opened caused
    LibreOffice to verify using the KeyValue but to report verification with the unrelated X509Data value.
    This issue affects: The Document Foundation LibreOffice 7.2 versions prior to 7.2.5. (CVE-2021-25636)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196456");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/KJ4E4JWVNOUJ5BNESH2IF34TBNSWMRGO/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?21bd215b");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-25636");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-25636");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-base-drivers-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-calc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-calc-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-draw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-filters-optional");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-gdb-pretty-printers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-glade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-icon-themes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-impress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-am");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-as");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ast");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-be");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-bn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-bn_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-bo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-brx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-bs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ca_valencia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ckb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-cy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-dgo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-dsb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-dz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-en_GB");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-en_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-eo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-fa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-fur");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-fy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-gu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-gug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-hi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-hsb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-id");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-is");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ka");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-kab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-kk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-km");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-kmr_Latn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-kn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-kok");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-lb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-lo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-lv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-mai");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-mk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-mn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-mni");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-mr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-my");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ne");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-nn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-nr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-nso");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-oc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-om");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-or");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-pa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-pt_BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-pt_PT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-rw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-sa_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-sat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-sd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-si");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-sid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-sq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-st");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-sw_TZ");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-szl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-te");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-tg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-th");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-tn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-tt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-uz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ve");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-vec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-xh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-zh_CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-zh_TW");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-zu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-librelogo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-mailmerge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-officebean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-pyuno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-qt5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-writer-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreofficekit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreofficekit-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/SuSE/release');
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
os_ver = os_ver[1];
if (release !~ "^(SUSE15\.3)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.3', release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + os_ver, cpu);

var pkgs = [
    {'reference':'libreoffice-7.2.5.1-150300.14.22.18.3', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-7.2.5.1-150300.14.22.18.3', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-base-7.2.5.1-150300.14.22.18.3', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-base-7.2.5.1-150300.14.22.18.3', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-base-drivers-postgresql-7.2.5.1-150300.14.22.18.3', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-base-drivers-postgresql-7.2.5.1-150300.14.22.18.3', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-branding-upstream-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-calc-7.2.5.1-150300.14.22.18.3', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-calc-7.2.5.1-150300.14.22.18.3', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-calc-extensions-7.2.5.1-150300.14.22.18.3', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-calc-extensions-7.2.5.1-150300.14.22.18.3', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-draw-7.2.5.1-150300.14.22.18.3', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-draw-7.2.5.1-150300.14.22.18.3', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-filters-optional-7.2.5.1-150300.14.22.18.3', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-filters-optional-7.2.5.1-150300.14.22.18.3', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-gdb-pretty-printers-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-glade-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-gnome-7.2.5.1-150300.14.22.18.3', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-gnome-7.2.5.1-150300.14.22.18.3', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-gtk3-7.2.5.1-150300.14.22.18.3', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-gtk3-7.2.5.1-150300.14.22.18.3', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-icon-themes-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-impress-7.2.5.1-150300.14.22.18.3', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-impress-7.2.5.1-150300.14.22.18.3', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-af-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-am-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-ar-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-as-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-ast-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-be-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-bg-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-bn-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-bn_IN-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-bo-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-br-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-brx-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-bs-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-ca-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-ca_valencia-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-ckb-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-cs-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-cy-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-da-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-de-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-dgo-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-dsb-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-dz-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-el-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-en-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-en_GB-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-en_ZA-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-eo-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-es-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-et-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-eu-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-fa-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-fi-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-fr-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-fur-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-fy-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-ga-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-gd-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-gl-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-gu-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-gug-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-he-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-hi-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-hr-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-hsb-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-hu-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-id-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-is-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-it-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-ja-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-ka-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-kab-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-kk-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-km-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-kmr_Latn-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-kn-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-ko-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-kok-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-ks-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-lb-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-lo-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-lt-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-lv-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-mai-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-mk-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-ml-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-mn-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-mni-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-mr-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-my-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-nb-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-ne-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-nl-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-nn-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-nr-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-nso-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-oc-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-om-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-or-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-pa-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-pl-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-pt_BR-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-pt_PT-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-ro-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-ru-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-rw-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-sa_IN-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-sat-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-sd-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-si-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-sid-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-sk-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-sl-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-sq-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-sr-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-ss-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-st-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-sv-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-sw_TZ-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-szl-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-ta-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-te-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-tg-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-th-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-tn-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-tr-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-ts-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-tt-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-ug-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-uk-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-uz-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-ve-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-vec-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-vi-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-xh-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-zh_CN-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-zh_TW-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-l10n-zu-7.2.5.1-150300.14.22.18.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-librelogo-7.2.5.1-150300.14.22.18.3', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-librelogo-7.2.5.1-150300.14.22.18.3', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-mailmerge-7.2.5.1-150300.14.22.18.3', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-mailmerge-7.2.5.1-150300.14.22.18.3', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-math-7.2.5.1-150300.14.22.18.3', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-math-7.2.5.1-150300.14.22.18.3', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-officebean-7.2.5.1-150300.14.22.18.3', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-officebean-7.2.5.1-150300.14.22.18.3', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-pyuno-7.2.5.1-150300.14.22.18.3', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-pyuno-7.2.5.1-150300.14.22.18.3', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-qt5-7.2.5.1-150300.14.22.18.3', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-qt5-7.2.5.1-150300.14.22.18.3', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-sdk-7.2.5.1-150300.14.22.18.3', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-sdk-7.2.5.1-150300.14.22.18.3', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-writer-7.2.5.1-150300.14.22.18.3', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-writer-7.2.5.1-150300.14.22.18.3', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-writer-extensions-7.2.5.1-150300.14.22.18.3', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-writer-extensions-7.2.5.1-150300.14.22.18.3', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreofficekit-7.2.5.1-150300.14.22.18.3', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreofficekit-7.2.5.1-150300.14.22.18.3', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreofficekit-devel-7.2.5.1-150300.14.22.18.3', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreofficekit-devel-7.2.5.1-150300.14.22.18.3', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var cpu = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release) {
    if (rpm_check(release:release, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libreoffice / libreoffice-base / libreoffice-base-drivers-postgresql / etc');
}
