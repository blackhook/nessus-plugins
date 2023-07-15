#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2020-b40fc174b5.
#

include("compat.inc");

if (description)
{
  script_id(141928);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/29");

  script_cve_id("CVE-2020-14352");
  script_xref(name:"FEDORA", value:"2020-b40fc174b5");

  script_name(english:"Fedora 33 : 1:livecd-tools / createrepo_c / dnf-plugins-core / etc (2020-b40fc174b5)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"createrepo_c 0.16.1

  - Update to 0.16.1

  - Add the section number to the manual pages

  - Parse xml snippet in smaller parts (RhBug:1859689)

  - Add module metadata support to createrepo_c
    (RhBug:1795936)

librepo 1.12.1

  - Update to 1.12.1

  - Validate path read from repomd.xml (RhBug:1868639)

libdnf 0.54.2

  - Update to 0.54.2

  - history: Fix dnf history rollback when a package was
    removed (RhBug:1683134)

  - Add support for HY_GT, HY_LT in query nevra_strict

  - Fix parsing empty lines in config files

  - Accept '==' as an operator in reldeps (RhBug:1847946)

  - Add log file level main config option (RhBug:1802074)

  - Add protect_running_kernel configuration option
    (RhBug:1698145)

  - Context part of libdnf cannot assume zchunk is on
    (RhBug:1851841,1779104)

  - Fix memory leak of resultingModuleIndex and handle
    g_object refs

  - Redirect librepo logs to libdnf logs with different
    source

  - Introduce changelog metadata in commit messages

  - Add hy_goal_lock

  - Update Copr targets for packit and use alias

  - Enum/String conversions for Transaction Store/Replay

  - utils: Add a method to decode URLs

  - Unify hawkey.log line format with the rest of the logs

dnf 4.4.0

  - Update to 4.4.0

  - Handle empty comps group name (RhBug:1826198)

  - Remove dead history info code (RhBug:1845800)

  - Improve command emmitter in dnf-automatic

  - Enhance --querytags and --qf help output

  - [history] add option --reverse to history list
    (RhBug:1846692)

  - Add logfilelevel configuration (RhBug:1802074)

  - Don't turn off stdout/stderr logging longer than
    necessary (RhBug:1843280)

  - Mention the date/time that updates were applied

  - [dnf-automatic] Wait for internet connection
    (RhBug:1816308)

  - [doc] Enhance repo variables documentation
    (RhBug:1848161,1848615)

  - Add librepo logger for handling messages from librepo
    (RhBug:1816573)

  - [doc] Add package-name-spec to the list of possible
    specs

  - [doc] Do not use <package-nevr-spec>

  - [doc] Add section to explain -n, -na and -nevra suffixes

  - Add alias 'ls' for list command

  - README: Reference Fedora Weblate instead of Zanata

  - remove log_lock.pid after reboot(Rhbug:1863006)

  - comps: Raise CompsError when removing a non-existent
    group

  - Add methods for working with comps to
    RPMTransactionItemWrapper

  - Implement storing and replaying a transaction

  - Log failure to access last makecache time as warning

  - [doc] Document Substitutions class

  - Dont document removed attribute ``reports`` for
    get_best_selector

  - Change the debug log timestamps from UTC to local time

dnf-plugins-core 4.0.18

  - [needs-restarting] Fix plugin fail if needs-restarting.d
    does not exist

  - [needs-restarting] add kernel-rt to reboot list

  - Fix debug-restore command

  - [config-manager] enable/disable comma separated pkgs
    (RhBug:1830530)

  - [debug] Use standard demands.resolving for transaction
    handling

  - [debug] Do not remove install-only packages
    (RhBug:1844533)

  - return error when dnf download failed

  - README: Reference Fedora Weblate instead of Zanata

  - [reposync] Add latest NEVRAs per stream to download
    (RhBug: 1833074)

  - copr: don't try to list runtime dependencies

dnf-plugins-extras 4.0.12

  - Update Cmake to pull translations from weblate

  - Drop Python 2 support

  - README: Add Installation, Contribution, etc

  - Add the DNF_SYSTEM_UPGRADE_NO_REBOOT env variable to
    control system-upgrade reboot.

  - [system-upgrade] Upgrade groups and environments
    (RhBug:1845562,1860408)

livecd-tools-27.1-8

  - Fix compatibility with dnf 4.4.0 / libdnf 0.54.2

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2020-b40fc174b5"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:1:livecd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:createrepo_c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:dnf-plugins-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:dnf-plugins-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:librepo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:33");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! preg(pattern:"^33([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 33", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC33", reference:"livecd-tools-27.1-8.fc33", epoch:"1")) flag++;
if (rpm_check(release:"FC33", reference:"createrepo_c-0.16.1-1.fc33")) flag++;
if (rpm_check(release:"FC33", reference:"dnf-plugins-core-4.0.18-1.fc33")) flag++;
if (rpm_check(release:"FC33", reference:"dnf-plugins-extras-4.0.12-1.fc33")) flag++;
if (rpm_check(release:"FC33", reference:"librepo-1.12.1-1.fc33")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "1:livecd-tools / createrepo_c / dnf-plugins-core / etc");
}
