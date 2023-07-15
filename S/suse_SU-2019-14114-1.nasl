#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2019:14114-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150610);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/10");
  script_xref(name:"SuSE", value:"SUSE-SU-2019:14114-1");

  script_name(english:"SUSE SLES11 Security Update : MozillaFirefox, mozilla-nss, mozilla-nspr (SUSE-SU-2019:14114-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES11 host has packages installed that are affected by a vulnerability as referenced in the SUSE-
SU-2019:14114-1 advisory. Note that Nessus has not tested for this issue but has instead relied only on the
application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1137338");
  # https://lists.suse.com/pipermail/sle-security-updates/2019-July/005661.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2a9b0aa0");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-branding-SLED");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox-at-spi2-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox-at-spi2-core-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox-atk-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox-dbus-1-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox-gdk-pixbuf-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox-gdk-pixbuf-query-loaders");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox-gdk-pixbuf-thumbnailer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox-gio-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox-glib2-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox-glib2-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox-gtk3-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox-gtk3-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox-gtk3-immodule-amharic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox-gtk3-immodule-inuktitut");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox-gtk3-immodule-multipress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox-gtk3-immodule-thai");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox-gtk3-immodule-vietnamese");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox-gtk3-immodule-xim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox-gtk3-immodules-tigrigna");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox-gtk3-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox-gtk3-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox-libatk-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox-libatk-bridge-2_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox-libatspi0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox-libcairo-gobject2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox-libcairo2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox-libfreetype6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox-libgcc_s1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox-libgdk_pixbuf-2_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox-libgtk-3-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox-libharfbuzz0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox-libpango-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox-libpixman-1-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox-libstdc++6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfirefox-gio-2_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfirefox-glib-2_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfirefox-gmodule-2_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfirefox-gobject-2_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfirefox-gthread-2_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfreebl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfreebl3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsoftokn3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsoftokn3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nspr-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-certs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-certs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES11', 'SUSE ' + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE ' + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! preg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP4", os_ver + " SP" + sp);

pkgs = [
    {'reference':'MozillaFirefox-60.7.0esr-78.40', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'MozillaFirefox-branding-SLED-60-21.6', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'MozillaFirefox-translations-common-60.7.0esr-78.40', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'MozillaFirefox-translations-other-60.7.0esr-78.40', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'firefox-at-spi2-core-2.10.2-2.6', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'firefox-at-spi2-core-lang-2.10.2-2.6', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'firefox-atk-lang-2.26.1-2.5', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'firefox-dbus-1-glib-0.76-34.2.4', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'firefox-gdk-pixbuf-lang-2.36.11-2.5', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'firefox-gdk-pixbuf-query-loaders-2.36.11-2.5', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'firefox-gdk-pixbuf-thumbnailer-2.36.11-2.5', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'firefox-gio-branding-upstream-2.54.3-2.4', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'firefox-glib2-lang-2.54.3-2.4', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'firefox-glib2-tools-2.54.3-2.4', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'firefox-gtk3-branding-upstream-3.10.9-2.8', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'firefox-gtk3-data-3.10.9-2.8', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'firefox-gtk3-immodule-amharic-3.10.9-2.8', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'firefox-gtk3-immodule-inuktitut-3.10.9-2.8', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'firefox-gtk3-immodule-multipress-3.10.9-2.8', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'firefox-gtk3-immodule-thai-3.10.9-2.8', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'firefox-gtk3-immodule-vietnamese-3.10.9-2.8', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'firefox-gtk3-immodule-xim-3.10.9-2.8', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'firefox-gtk3-immodules-tigrigna-3.10.9-2.8', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'firefox-gtk3-lang-3.10.9-2.8', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'firefox-gtk3-tools-3.10.9-2.8', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'firefox-libatk-1_0-0-2.26.1-2.5', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'firefox-libatk-bridge-2_0-0-2.10.2-2.6', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'firefox-libatspi0-2.10.2-2.6', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'firefox-libcairo-gobject2-1.15.10-2.8', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'firefox-libcairo2-1.15.10-2.8', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'firefox-libfreetype6-2.9-2.4', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'firefox-libgcc_s1-5.3.1+r233831-10', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'firefox-libgcc_s1-5.3.1+r233831-10', 'sp':'4', 'cpu':'s390x', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'firefox-libgdk_pixbuf-2_0-0-2.36.11-2.5', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'firefox-libgtk-3-0-3.10.9-2.8', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'firefox-libharfbuzz0-1.7.5-2.4', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'firefox-libpango-1_0-0-1.40.14-2.4', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'firefox-libpixman-1-0-0.34.0-2.5', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'firefox-libstdc++6-5.3.1+r233831-10', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'firefox-libstdc++6-5.3.1+r233831-10', 'sp':'4', 'cpu':'s390x', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'libfirefox-gio-2_0-0-2.54.3-2.4', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'libfirefox-glib-2_0-0-2.54.3-2.4', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'libfirefox-gmodule-2_0-0-2.54.3-2.4', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'libfirefox-gobject-2_0-0-2.54.3-2.4', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'libfirefox-gthread-2_0-0-2.54.3-2.4', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'libfreebl3-3.41.1-38.6', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'libfreebl3-32bit-3.41.1-38.6', 'sp':'4', 'cpu':'s390x', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'libfreebl3-32bit-3.41.1-38.6', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'libsoftokn3-3.41.1-38.6', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'libsoftokn3-32bit-3.41.1-38.6', 'sp':'4', 'cpu':'s390x', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'libsoftokn3-32bit-3.41.1-38.6', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'mozilla-nspr-32bit-4.20-29.3', 'sp':'4', 'cpu':'s390x', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'mozilla-nspr-32bit-4.20-29.3', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'mozilla-nspr-4.20-29.3', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'mozilla-nspr-devel-4.20-29.3', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'mozilla-nss-3.41.1-38.6', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'mozilla-nss-32bit-3.41.1-38.6', 'sp':'4', 'cpu':'s390x', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'mozilla-nss-32bit-3.41.1-38.6', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'mozilla-nss-certs-3.41.1-38.6', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'mozilla-nss-certs-32bit-3.41.1-38.6', 'sp':'4', 'cpu':'s390x', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'mozilla-nss-certs-32bit-3.41.1-38.6', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'mozilla-nss-devel-3.41.1-38.6', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'mozilla-nss-tools-3.41.1-38.6', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'MozillaFirefox-60.7.0esr-78.40', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'MozillaFirefox-branding-SLED-60-21.6', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'MozillaFirefox-translations-common-60.7.0esr-78.40', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'MozillaFirefox-translations-other-60.7.0esr-78.40', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'firefox-at-spi2-core-2.10.2-2.6', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'firefox-at-spi2-core-lang-2.10.2-2.6', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'firefox-atk-lang-2.26.1-2.5', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'firefox-dbus-1-glib-0.76-34.2.4', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'firefox-gdk-pixbuf-lang-2.36.11-2.5', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'firefox-gdk-pixbuf-query-loaders-2.36.11-2.5', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'firefox-gdk-pixbuf-thumbnailer-2.36.11-2.5', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'firefox-gio-branding-upstream-2.54.3-2.4', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'firefox-glib2-lang-2.54.3-2.4', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'firefox-glib2-tools-2.54.3-2.4', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'firefox-gtk3-branding-upstream-3.10.9-2.8', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'firefox-gtk3-data-3.10.9-2.8', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'firefox-gtk3-immodule-amharic-3.10.9-2.8', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'firefox-gtk3-immodule-inuktitut-3.10.9-2.8', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'firefox-gtk3-immodule-multipress-3.10.9-2.8', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'firefox-gtk3-immodule-thai-3.10.9-2.8', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'firefox-gtk3-immodule-vietnamese-3.10.9-2.8', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'firefox-gtk3-immodule-xim-3.10.9-2.8', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'firefox-gtk3-immodules-tigrigna-3.10.9-2.8', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'firefox-gtk3-lang-3.10.9-2.8', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'firefox-gtk3-tools-3.10.9-2.8', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'firefox-libatk-1_0-0-2.26.1-2.5', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'firefox-libatk-bridge-2_0-0-2.10.2-2.6', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'firefox-libatspi0-2.10.2-2.6', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'firefox-libcairo-gobject2-1.15.10-2.8', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'firefox-libcairo2-1.15.10-2.8', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'firefox-libfreetype6-2.9-2.4', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'firefox-libgcc_s1-5.3.1+r233831-10', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'firefox-libgcc_s1-5.3.1+r233831-10', 'sp':'4', 'cpu':'s390x', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'firefox-libgdk_pixbuf-2_0-0-2.36.11-2.5', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'firefox-libgtk-3-0-3.10.9-2.8', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'firefox-libharfbuzz0-1.7.5-2.4', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'firefox-libpango-1_0-0-1.40.14-2.4', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'firefox-libpixman-1-0-0.34.0-2.5', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'firefox-libstdc++6-5.3.1+r233831-10', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'firefox-libstdc++6-5.3.1+r233831-10', 'sp':'4', 'cpu':'s390x', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'libfirefox-gio-2_0-0-2.54.3-2.4', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'libfirefox-glib-2_0-0-2.54.3-2.4', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'libfirefox-gmodule-2_0-0-2.54.3-2.4', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'libfirefox-gobject-2_0-0-2.54.3-2.4', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'libfirefox-gthread-2_0-0-2.54.3-2.4', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'libfreebl3-3.41.1-38.6', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'libfreebl3-32bit-3.41.1-38.6', 'sp':'4', 'cpu':'s390x', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'libfreebl3-32bit-3.41.1-38.6', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'libsoftokn3-3.41.1-38.6', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'libsoftokn3-32bit-3.41.1-38.6', 'sp':'4', 'cpu':'s390x', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'libsoftokn3-32bit-3.41.1-38.6', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'mozilla-nspr-32bit-4.20-29.3', 'sp':'4', 'cpu':'s390x', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'mozilla-nspr-32bit-4.20-29.3', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'mozilla-nspr-4.20-29.3', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'mozilla-nspr-devel-4.20-29.3', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'mozilla-nss-3.41.1-38.6', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'mozilla-nss-32bit-3.41.1-38.6', 'sp':'4', 'cpu':'s390x', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'mozilla-nss-32bit-3.41.1-38.6', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'mozilla-nss-certs-3.41.1-38.6', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'mozilla-nss-certs-32bit-3.41.1-38.6', 'sp':'4', 'cpu':'s390x', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'mozilla-nss-certs-32bit-3.41.1-38.6', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'mozilla-nss-devel-3.41.1-38.6', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'mozilla-nss-tools-3.41.1-38.6', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  sp = NULL;
  cpu = NULL;
  exists_check = NULL;
  rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release && exists_check) {
    if (rpm_exists(release:release, rpm:exists_check) && rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
  else if (reference && release) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  ltss_plugin_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in SUSE Enterprise Linux Server LTSS\n' +
    'repositories. Access to these package security updates require\n' +
    'a paid SUSE LTSS subscription.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'MozillaFirefox / MozillaFirefox-branding-SLED / etc');
}
