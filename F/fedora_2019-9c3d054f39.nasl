#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2019-9c3d054f39.
#

include("compat.inc");

if (description)
{
  script_id(132084);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id("CVE-2019-1348", "CVE-2019-1349", "CVE-2019-1350", "CVE-2019-1351", "CVE-2019-1352", "CVE-2019-1353", "CVE-2019-1354", "CVE-2019-1387");
  script_xref(name:"FEDORA", value:"2019-9c3d054f39");

  script_name(english:"Fedora 31 : libgit2 (2019-9c3d054f39)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This is a security release fixing the following issues :

  - CVE-2019-1348: the fast-import stream command 'feature
    export-marks=path' allows writing to arbitrary file
    paths. As libgit2 does not offer any interface for
    fast-import, it is not susceptible to this
    vulnerability.

  - CVE-2019-1349: by using NTFS 8.3 short names,
    backslashes or alternate filesystreams, it is possible
    to cause submodules to be written into pre-existing
    directories during a recursive clone using git. As
    libgit2 rejects cloning into non-empty directories by
    default, it is not susceptible to this vulnerability.

  - CVE-2019-1350: recursive clones may lead to arbitrary
    remote code executing due to improper quoting of command
    line arguments. As libgit2 uses libssh2, which does not
    require us to perform command line parsing, it is not
    susceptible to this vulnerability.

  - CVE-2019-1351: Windows provides the ability to
    substitute drive letters with arbitrary letters,
    including multi-byte Unicode letters. To fix any
    potential issues arising from interpreting such paths as
    relative paths, we have extended detection of DOS drive
    prefixes to accomodate for such cases.

  - CVE-2019-1352: by using NTFS-style alternative file
    streams for the '.git' directory, it is possible to
    overwrite parts of the repository. While this has been
    fixed in the past for Windows, the same vulnerability
    may also exist on other systems that write to NTFS
    filesystems. We now reject any paths starting with
    '.git:' on all systems.

  - CVE-2019-1353: by using NTFS-style 8.3 short names, it
    was possible to write to the '.git' directory and thus
    overwrite parts of the repository, leading to possible
    remote code execution. While this problem was already
    fixed in the past for Windows, other systems accessing
    NTFS filesystems are vulnerable to this issue too. We
    now enable NTFS protecions by default on all systems to
    fix this attack vector.

  - CVE-2019-1354: on Windows, backslashes are not a valid
    part of a filename but are instead interpreted as
    directory separators. As other platforms allowed to use
    such paths, it was possible to write such invalid
    entries into a Git repository and was thus an attack
    vector to write into the '.git' dierctory. We now reject
    any entries starting with '.git' on all systems.

  - CVE-2019-1387: it is possible to let a submodule's git
    directory point into a sibling's submodule directory,
    which may result in overwriting parts of the Git
    repository and thus lead to arbitrary command execution.
    As libgit2 doesn't provide any way to do submodule
    clones natively, it is not susceptible to this
    vulnerability. Users of libgit2 that have implemented
    recursive submodule clones manually are encouraged to
    review their implementation for this vulnerability.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2019-9c3d054f39"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected libgit2 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1354");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libgit2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:31");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/17");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^31([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 31", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC31", reference:"libgit2-0.28.4-1.fc31")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libgit2");
}
