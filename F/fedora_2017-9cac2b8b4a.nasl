#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2017-9cac2b8b4a.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(105937);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_xref(name:"FEDORA", value:"2017-9cac2b8b4a");

  script_name(english:"Fedora 27 : fedpkg / rpkg (2017-9cac2b8b4a)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"**Update**

  - Fixed chain-build

  - Remove hard dependency of bash-completion from fedpkg

**rpkg**

  - Ignore TestModulesCli if openidc-client is unavailable
    (cqi)

  - Port mbs-build to rpkg (mprahl)

  - Add .vscode to .gitignore (mprahl)

  - Fix TestPatch.test_rediff in order to run with old
    version of mock (cqi)

  - Allow to specify alternative Copr config file - #184
    (cqi)

  - Tests for patch command (cqi)

  - More Tests for mockbuild command (cqi)

  - More tests for getting spec file (cqi)

  - Tests for container-build-setup command (cqi)

  - Test for container-build to use custom config (cqi)

  - Suppress output from git command within setUp (cqi)

  - Skip test if rpmfluff is not available (lsedlar)

  - Allow to override build URL (cqi)

  - Test for mock-config command (cqi)

  - Tests for copr-build command (cqi)

  - Fix arch-override for container-build (lucarval)

  - Remove unsupported osbs for container-build (lucarval)

  - cli: add --arches support for koji_cointainerbuild
    (mlangsdo)

  - Strip refs/heads/ from branch only once (lsedlar)

  - Don't install bin and config files (cqi)

  - Fix kojiprofile selection in
    cliClient.container_build_koji (cqi)

  - Avoid branch detection for 'rpkg sources' (praiskup)

  - Fix encoding in new command (cqi)

  - Minor wording improvement in help (pgier)

  - Fix indentation (pviktori)

  - Add --with and --without options to mockbuild (pviktori)

**fedpkg**

  - Tests for update command (cqi)

  - Add support for module commands (mprahl)

  - Clean rest cert related code (cqi)

  - Remove fedora cert (cqi)

  - Override build URL for Koji (cqi)

  - changing anongiturl to use src.fp.o instead of
    pkgs.fp.o. - #119 (tflink)

  - Add tests (cqi)

  - Enable lookaside_namespaced - #130 (cqi)

  - Detect dist tag correctly for RHEL and CentOS - #141
    (cqi)

  - Remove deprecated call to platform.dist (cqi)

  - Do not prompt hint for SSL cert if fail to log into Koji
    (cqi)

  - Add more container-build options to bash completion
    (cqi)

  - Remove osbs from bash completion - #138 (cqi)

  - Install executables via entry_points - #134 (cqi)

  - Fix container build target (lsedlar)

  - Get correct build target for rawhide containers
    (lsedlar)

  - Update error message to reflect deprecation of --dist
    option (pgier)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2017-9cac2b8b4a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected fedpkg and / or rpkg packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:fedpkg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rpkg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:27");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^27([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 27", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC27", reference:"fedpkg-1.30-4.fc27")) flag++;
if (rpm_check(release:"FC27", reference:"rpkg-1.51-2.fc27")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "fedpkg / rpkg");
}
