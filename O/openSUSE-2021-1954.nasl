#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2021:1954-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151692);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/16");

  script_cve_id(
    "CVE-2021-21284",
    "CVE-2021-21285",
    "CVE-2021-21334",
    "CVE-2021-30465"
  );

  script_name(english:"openSUSE 15 Security Update : containerd, docker, runc (openSUSE-SU-2021:1954-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2021:1954-1 advisory.

  - In Docker before versions 9.03.15, 20.10.3 there is a vulnerability involving the --userns-remap option in
    which access to remapped root allows privilege escalation to real root. When using --userns-remap, if
    the root user in the remapped namespace has access to the host filesystem they can modify files under
    /var/lib/docker/ that cause writing files with extended privileges. Versions 20.10.3 and
    19.03.15 contain patches that prevent privilege escalation from remapped user. (CVE-2021-21284)

  - In Docker before versions 9.03.15, 20.10.3 there is a vulnerability in which pulling an intentionally
    malformed Docker image manifest crashes the dockerd daemon. Versions 20.10.3 and 19.03.15 contain patches
    that prevent the daemon from crashing. (CVE-2021-21285)

  - In containerd (an industry-standard container runtime) before versions 1.3.10 and 1.4.4, containers
    launched through containerd's CRI implementation (through Kubernetes, crictl, or any other pod/container
    client that uses the containerd CRI service) that share the same image may receive incorrect environment
    variables, including values that are defined for other containers. If the affected containers have
    different security contexts, this may allow sensitive information to be unintentionally shared. If you are
    not using containerd's CRI implementation (through one of the mechanisms described above), you are not
    vulnerable to this issue. If you are not launching multiple containers or Kubernetes pods from the same
    image which have different environment variables, you are not vulnerable to this issue. If you are not
    launching multiple containers or Kubernetes pods from the same image in rapid succession, you have reduced
    likelihood of being vulnerable to this issue This vulnerability has been fixed in containerd 1.3.10 and
    containerd 1.4.4. Users should update to these versions. (CVE-2021-21334)

  - runc before 1.0.0-rc95 allows a Container Filesystem Breakout via Directory Traversal. To exploit the
    vulnerability, an attacker must be able to create multiple containers with a fairly specific mount
    configuration. The problem occurs via a symlink-exchange attack that relies on a race condition.
    (CVE-2021-30465)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1168481");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1175081");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1175821");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181594");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181641");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181677");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181730");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181732");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181749");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182451");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182476");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182947");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183024");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183855");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184768");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184962");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185405");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/OX775QFGRPXXX7W5FDFKP3V5KCNZYD7F/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?55f744b3");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-21284");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-21285");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-21334");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30465");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-30465");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:containerd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:containerd-ctr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-fish-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-zsh-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:runc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
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
release = get_kb_item('Host/SuSE/release');
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
os_ver = os_ver[1];
if (release !~ "^(SUSE15\.3)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.3', release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + os_ver, cpu);

pkgs = [
    {'reference':'containerd-1.4.4-5.32.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'containerd-ctr-1.4.4-5.32.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'docker-20.10.6_ce-6.49.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'docker-bash-completion-20.10.6_ce-6.49.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'docker-fish-completion-20.10.6_ce-6.49.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'docker-zsh-completion-20.10.6_ce-6.49.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'runc-1.0.0~rc93-1.14.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  cpu = NULL;
  rpm_spec_vers_cmp = NULL;
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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'containerd / containerd-ctr / docker / docker-bash-completion / etc');
}
