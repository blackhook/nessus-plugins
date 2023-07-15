##
# (C) Tenable Network Security, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2021-09ce0cdfac
#

include('compat.inc');

if (description)
{
  script_id(146471);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/10");

  script_cve_id(
    "CVE-2020-25650",
    "CVE-2020-25651",
    "CVE-2020-25652",
    "CVE-2020-25653"
  );
  script_xref(name:"FEDORA", value:"2021-09ce0cdfac");

  script_name(english:"Fedora 33 : spice-vdagent (2021-09ce0cdfac)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 33 host has a package installed that is affected by multiple vulnerabilities as referenced in the
FEDORA-2021-09ce0cdfac advisory.

  - A flaw was found in the way the spice-vdagentd daemon handled file transfers from the host system to the
    virtual machine. Any unprivileged local guest user with access to the UNIX domain socket path `/run/spice-
    vdagentd/spice-vdagent-sock` could use this flaw to perform a memory denial of service for spice-vdagentd
    or even other processes in the VM system. The highest threat from this vulnerability is to system
    availability. This flaw affects spice-vdagent versions 0.20 and previous versions. (CVE-2020-25650)

  - A flaw was found in the SPICE file transfer protocol. File data from the host system can end up in full or
    in parts in the client connection of an illegitimate local user in the VM system. Active file transfers
    from other users could also be interrupted, resulting in a denial of service. The highest threat from this
    vulnerability is to data confidentiality as well as system availability. This flaw affects spice-vdagent
    versions 0.20 and prior. (CVE-2020-25651)

  - A flaw was found in the spice-vdagentd daemon, where it did not properly handle client connections that
    can be established via the UNIX domain socket in `/run/spice-vdagentd/spice-vdagent-sock`. Any
    unprivileged local guest user could use this flaw to prevent legitimate agents from connecting to the
    spice-vdagentd daemon, resulting in a denial of service. The highest threat from this vulnerability is to
    system availability. This flaw affects spice-vdagent versions 0.20 and prior. (CVE-2020-25652)

  - A race condition vulnerability was found in the way the spice-vdagentd daemon handled new client
    connections. This flaw may allow an unprivileged local guest user to become the active agent for spice-
    vdagentd, possibly resulting in a denial of service or information leakage from the host. The highest
    threat from this vulnerability is to data confidentiality as well as system availability. This flaw
    affects spice-vdagent versions 0.20 and prior. (CVE-2020-25653)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2021-09ce0cdfac");
  script_set_attribute(attribute:"solution", value:
"Update the affected spice-vdagent package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25653");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-25651");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:33");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:spice-vdagent");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'spice-vdagent-0.21.0-1.fc33', 'release':'FC33', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'spice-vdagent');
}
