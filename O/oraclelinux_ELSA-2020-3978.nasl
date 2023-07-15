##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2020-3978.
##

include('compat.inc');

if (description)
{
  script_id(141220);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/09");

  script_cve_id("CVE-2019-12450", "CVE-2019-14822");

  script_name(english:"Oracle Linux 7 : glib2 / and / ibus (ELSA-2020-3978)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2020-3978 advisory.

  - file_copy_fallback in gio/gfile.c in GNOME GLib 2.15.0 through 2.61.1 does not properly restrict file
    permissions while a copy operation is in progress. Instead, default permissions are used. (CVE-2019-12450)

  - A flaw was discovered in ibus in versions before 1.5.22 that allows any unprivileged user to monitor and
    send method calls to the ibus bus of another user due to a misconfiguration in the DBus server setup. A
    local attacker may use this flaw to intercept all keystrokes of a victim user who is using the graphical
    interface, change the input method engine, or modify other input related configurations of the victim
    user. (CVE-2019-14822)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://linux.oracle.com/errata/ELSA-2020-3978.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12450");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glib2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glib2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glib2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glib2-fam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glib2-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glib2-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ibus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ibus-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ibus-devel-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ibus-gtk2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ibus-gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ibus-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ibus-pygtk2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ibus-setup");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 7', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

pkgs = [
    {'reference':'glib2-2.56.1-7.el7', 'cpu':'aarch64', 'release':'7'},
    {'reference':'glib2-2.56.1-7.el7', 'cpu':'i686', 'release':'7'},
    {'reference':'glib2-2.56.1-7.el7', 'cpu':'x86_64', 'release':'7'},
    {'reference':'glib2-devel-2.56.1-7.el7', 'cpu':'aarch64', 'release':'7'},
    {'reference':'glib2-devel-2.56.1-7.el7', 'cpu':'i686', 'release':'7'},
    {'reference':'glib2-devel-2.56.1-7.el7', 'cpu':'x86_64', 'release':'7'},
    {'reference':'glib2-doc-2.56.1-7.el7', 'release':'7'},
    {'reference':'glib2-fam-2.56.1-7.el7', 'cpu':'aarch64', 'release':'7'},
    {'reference':'glib2-fam-2.56.1-7.el7', 'cpu':'x86_64', 'release':'7'},
    {'reference':'glib2-static-2.56.1-7.el7', 'cpu':'aarch64', 'release':'7'},
    {'reference':'glib2-static-2.56.1-7.el7', 'cpu':'i686', 'release':'7'},
    {'reference':'glib2-static-2.56.1-7.el7', 'cpu':'x86_64', 'release':'7'},
    {'reference':'glib2-tests-2.56.1-7.el7', 'cpu':'aarch64', 'release':'7'},
    {'reference':'glib2-tests-2.56.1-7.el7', 'cpu':'x86_64', 'release':'7'},
    {'reference':'ibus-1.5.17-11.el7', 'cpu':'aarch64', 'release':'7'},
    {'reference':'ibus-1.5.17-11.el7', 'cpu':'i686', 'release':'7'},
    {'reference':'ibus-1.5.17-11.el7', 'cpu':'x86_64', 'release':'7'},
    {'reference':'ibus-devel-1.5.17-11.el7', 'cpu':'aarch64', 'release':'7'},
    {'reference':'ibus-devel-1.5.17-11.el7', 'cpu':'i686', 'release':'7'},
    {'reference':'ibus-devel-1.5.17-11.el7', 'cpu':'x86_64', 'release':'7'},
    {'reference':'ibus-devel-docs-1.5.17-11.el7', 'release':'7'},
    {'reference':'ibus-gtk2-1.5.17-11.el7', 'cpu':'aarch64', 'release':'7'},
    {'reference':'ibus-gtk2-1.5.17-11.el7', 'cpu':'i686', 'release':'7'},
    {'reference':'ibus-gtk2-1.5.17-11.el7', 'cpu':'x86_64', 'release':'7'},
    {'reference':'ibus-gtk3-1.5.17-11.el7', 'cpu':'aarch64', 'release':'7'},
    {'reference':'ibus-gtk3-1.5.17-11.el7', 'cpu':'i686', 'release':'7'},
    {'reference':'ibus-gtk3-1.5.17-11.el7', 'cpu':'x86_64', 'release':'7'},
    {'reference':'ibus-libs-1.5.17-11.el7', 'cpu':'aarch64', 'release':'7'},
    {'reference':'ibus-libs-1.5.17-11.el7', 'cpu':'i686', 'release':'7'},
    {'reference':'ibus-libs-1.5.17-11.el7', 'cpu':'x86_64', 'release':'7'},
    {'reference':'ibus-pygtk2-1.5.17-11.el7', 'release':'7'},
    {'reference':'ibus-setup-1.5.17-11.el7', 'release':'7'}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  sp = NULL;
  cpu = NULL;
  el_string = NULL;
  rpm_spec_vers_cmp = NULL;
  epoch = NULL;
  allowmaj = NULL;
  rpm_prefix = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['rpm_prefix'])) rpm_prefix = package_array['rpm_prefix'];
  if (reference && release) {
    if (rpm_prefix) {
        if (rpm_exists(release:release, rpm:rpm_prefix) && rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'glib2 / glib2-devel / glib2-doc / etc');
}