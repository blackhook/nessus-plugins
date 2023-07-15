##
# (C) Tenable Network Security, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2021-26ad138ffa
#

include('compat.inc');

if (description)
{
  script_id(147940);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/12");

  script_cve_id("CVE-2021-21381");
  script_xref(name:"FEDORA", value:"2021-26ad138ffa");

  script_name(english:"Fedora 33 : flatpak (2021-26ad138ffa)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 33 host has a package installed that is affected by multiple vulnerabilities as referenced in the
FEDORA-2021-26ad138ffa advisory.

  - Flatpak is a system for building, distributing, and running sandboxed desktop applications on Linux. In
    Flatpack since version 0.9.4 and before version 1.10.2 has a vulnerability in the file forwarding
    feature which can be used by an attacker to gain access to files that would not ordinarily be allowed by
    the app's permissions. By putting the special tokens `@@` and/or `@@u` in the Exec field of a Flatpak
    app's .desktop file, a malicious app publisher can trick flatpak into behaving as though the user had
    chosen to open a target file with their Flatpak app, which automatically makes that file available to the
    Flatpak app. This is fixed in version 1.10.2. A minimal solution is the first commit `Disallow @@ and @@U
    usage in desktop files`. The follow-up commits `dir: Reserve the whole @@ prefix` and `dir: Refuse to
    export .desktop files with suspicious uses of @@ tokens` are recommended, but not strictly required. As a
    workaround, avoid installing Flatpak apps from untrusted sources, or check the contents of the exported
    `.desktop` files in `exports/share/applications/*.desktop` (typically
    `~/.local/share/flatpak/exports/share/applications/*.desktop` and
    `/var/lib/flatpak/exports/share/applications/*.desktop`) to make sure that literal filenames do not follow
    `@@` or `@@u`. (CVE-2021-21381)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2021-26ad138ffa");
  script_set_attribute(attribute:"solution", value:
"Update the affected flatpak package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21381");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:33");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:flatpak");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/RedHat/release');
if (isnull(release) || 'Fedora' >!< release) audit(AUDIT_OS_NOT, 'Fedora');
os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Fedora');
os_ver = os_ver[1];
if (! preg(pattern:"^33([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 33', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

pkgs = [
    {'reference':'flatpak-1.10.2-1.fc33', 'release':'FC33', 'rpm_spec_vers_cmp':TRUE}
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
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && release) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'flatpak');
}
