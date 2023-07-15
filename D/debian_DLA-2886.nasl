#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2886. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156773);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/17");

  script_cve_id(
    "CVE-2019-12838",
    "CVE-2020-12693",
    "CVE-2020-27745",
    "CVE-2021-31215"
  );

  script_name(english:"Debian DLA-2886-1 : slurm-llnl - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-2886 advisory.

  - SchedMD Slurm 17.11.x, 18.08.0 through 18.08.7, and 19.05.0 allows SQL Injection. (CVE-2019-12838)

  - Slurm 19.05.x before 19.05.7 and 20.02.x before 20.02.3, in the rare case where Message Aggregation is
    enabled, allows Authentication Bypass via an Alternate Path or Channel. A race condition allows a user to
    launch a process as an arbitrary user. (CVE-2020-12693)

  - Slurm before 19.05.8 and 20.x before 20.02.6 has an RPC Buffer Overflow in the PMIx MPI plugin.
    (CVE-2020-27745)

  - SchedMD Slurm before 20.02.7 and 20.03.x through 20.11.x before 20.11.7 allows remote code execution as
    SlurmUser because use of a PrologSlurmctld or EpilogSlurmctld script leads to environment mishandling.
    (CVE-2021-31215)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=931880");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/slurm-llnl");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-2886");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-12838");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-12693");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-27745");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-31215");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/slurm-llnl");
  script_set_attribute(attribute:"solution", value:
"Upgrade the slurm-llnl packages.

For Debian 9 stretch, these problems have been fixed in version 16.05.9-1+deb9u5.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12838");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpam-slurm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpmi0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpmi0-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpmi0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpmi2-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpmi2-0-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpmi2-0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libslurm-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libslurm-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libslurm30");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libslurm30-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libslurmdb-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libslurmdb-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libslurmdb30");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libslurmdb30-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:slurm-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:slurm-client-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:slurm-client-emulator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:slurm-llnl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:slurm-llnl-slurmdbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:slurm-wlm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:slurm-wlm-basic-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:slurm-wlm-basic-plugins-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:slurm-wlm-basic-plugins-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:slurm-wlm-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:slurm-wlm-emulator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:slurm-wlm-torque");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:slurmctld");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:slurmctld-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:slurmd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:slurmd-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:slurmdbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:slurmdbd-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sview");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
var release = chomp(release);
if (! preg(pattern:"^(9)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 9.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '9.0', 'prefix': 'libpam-slurm', 'reference': '16.05.9-1+deb9u5'},
    {'release': '9.0', 'prefix': 'libpmi0', 'reference': '16.05.9-1+deb9u5'},
    {'release': '9.0', 'prefix': 'libpmi0-dbg', 'reference': '16.05.9-1+deb9u5'},
    {'release': '9.0', 'prefix': 'libpmi0-dev', 'reference': '16.05.9-1+deb9u5'},
    {'release': '9.0', 'prefix': 'libpmi2-0', 'reference': '16.05.9-1+deb9u5'},
    {'release': '9.0', 'prefix': 'libpmi2-0-dbg', 'reference': '16.05.9-1+deb9u5'},
    {'release': '9.0', 'prefix': 'libpmi2-0-dev', 'reference': '16.05.9-1+deb9u5'},
    {'release': '9.0', 'prefix': 'libslurm-dev', 'reference': '16.05.9-1+deb9u5'},
    {'release': '9.0', 'prefix': 'libslurm-perl', 'reference': '16.05.9-1+deb9u5'},
    {'release': '9.0', 'prefix': 'libslurm30', 'reference': '16.05.9-1+deb9u5'},
    {'release': '9.0', 'prefix': 'libslurm30-dbg', 'reference': '16.05.9-1+deb9u5'},
    {'release': '9.0', 'prefix': 'libslurmdb-dev', 'reference': '16.05.9-1+deb9u5'},
    {'release': '9.0', 'prefix': 'libslurmdb-perl', 'reference': '16.05.9-1+deb9u5'},
    {'release': '9.0', 'prefix': 'libslurmdb30', 'reference': '16.05.9-1+deb9u5'},
    {'release': '9.0', 'prefix': 'libslurmdb30-dbg', 'reference': '16.05.9-1+deb9u5'},
    {'release': '9.0', 'prefix': 'slurm-client', 'reference': '16.05.9-1+deb9u5'},
    {'release': '9.0', 'prefix': 'slurm-client-dbg', 'reference': '16.05.9-1+deb9u5'},
    {'release': '9.0', 'prefix': 'slurm-client-emulator', 'reference': '16.05.9-1+deb9u5'},
    {'release': '9.0', 'prefix': 'slurm-llnl', 'reference': '16.05.9-1+deb9u5'},
    {'release': '9.0', 'prefix': 'slurm-llnl-slurmdbd', 'reference': '16.05.9-1+deb9u5'},
    {'release': '9.0', 'prefix': 'slurm-wlm', 'reference': '16.05.9-1+deb9u5'},
    {'release': '9.0', 'prefix': 'slurm-wlm-basic-plugins', 'reference': '16.05.9-1+deb9u5'},
    {'release': '9.0', 'prefix': 'slurm-wlm-basic-plugins-dbg', 'reference': '16.05.9-1+deb9u5'},
    {'release': '9.0', 'prefix': 'slurm-wlm-basic-plugins-dev', 'reference': '16.05.9-1+deb9u5'},
    {'release': '9.0', 'prefix': 'slurm-wlm-doc', 'reference': '16.05.9-1+deb9u5'},
    {'release': '9.0', 'prefix': 'slurm-wlm-emulator', 'reference': '16.05.9-1+deb9u5'},
    {'release': '9.0', 'prefix': 'slurm-wlm-torque', 'reference': '16.05.9-1+deb9u5'},
    {'release': '9.0', 'prefix': 'slurmctld', 'reference': '16.05.9-1+deb9u5'},
    {'release': '9.0', 'prefix': 'slurmctld-dbg', 'reference': '16.05.9-1+deb9u5'},
    {'release': '9.0', 'prefix': 'slurmd', 'reference': '16.05.9-1+deb9u5'},
    {'release': '9.0', 'prefix': 'slurmd-dbg', 'reference': '16.05.9-1+deb9u5'},
    {'release': '9.0', 'prefix': 'slurmdbd', 'reference': '16.05.9-1+deb9u5'},
    {'release': '9.0', 'prefix': 'slurmdbd-dbg', 'reference': '16.05.9-1+deb9u5'},
    {'release': '9.0', 'prefix': 'sview', 'reference': '16.05.9-1+deb9u5'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (release && prefix && reference) {
    if (deb_check(release:release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libpam-slurm / libpmi0 / libpmi0-dbg / libpmi0-dev / libpmi2-0 / etc');
}
