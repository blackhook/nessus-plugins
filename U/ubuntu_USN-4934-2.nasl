#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4934-2. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149323);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2020-28007",
    "CVE-2020-28008",
    "CVE-2020-28009",
    "CVE-2020-28011",
    "CVE-2020-28012",
    "CVE-2020-28013",
    "CVE-2020-28014",
    "CVE-2020-28015",
    "CVE-2020-28016",
    "CVE-2020-28017",
    "CVE-2020-28020",
    "CVE-2020-28022",
    "CVE-2020-28024",
    "CVE-2020-28025",
    "CVE-2020-28026",
    "CVE-2021-27216"
  );
  script_xref(name:"USN", value:"4934-2");
  script_xref(name:"IAVA", value:"2021-A-0216-S");

  script_name(english:"Ubuntu 16.04 LTS : Exim vulnerabilities (USN-4934-2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-4934-2 advisory.

  - Exim 4 before 4.94.2 allows Execution with Unnecessary Privileges. Because Exim operates as root in the
    log directory (owned by a non-root user), a symlink or hard link attack allows overwriting critical root-
    owned files anywhere on the filesystem. (CVE-2020-28007)

  - Exim 4 before 4.94.2 allows Execution with Unnecessary Privileges. Because Exim operates as root in the
    spool directory (owned by a non-root user), an attacker can write to a /var/spool/exim4/input spool header
    file, in which a crafted recipient address can indirectly lead to command execution. (CVE-2020-28008)

  - Exim 4 before 4.94.2 allows Integer Overflow to Buffer Overflow because get_stdinput allows unbounded
    reads that are accompanied by unbounded increases in a certain size variable. NOTE: exploitation may be
    impractical because of the execution time needed to overflow (multiple days). (CVE-2020-28009)

  - Exim 4 before 4.94.2 allows Heap-based Buffer Overflow in queue_run via two sender options: -R and -S.
    This may cause privilege escalation from exim to root. (CVE-2020-28011)

  - Exim 4 before 4.94.2 allows Exposure of File Descriptor to Unintended Control Sphere because rda_interpret
    uses a privileged pipe that lacks a close-on-exec flag. (CVE-2020-28012)

  - Exim 4 before 4.94.2 allows Heap-based Buffer Overflow because it mishandles -F '.(' on the command
    line, and thus may allow privilege escalation from any user to root. This occurs because of the
    interpretation of negative sizes in strncpy. (CVE-2020-28013)

  - Exim 4 before 4.94.2 allows Execution with Unnecessary Privileges. The -oP option is available to the exim
    user, and allows a denial of service because root-owned files can be overwritten. (CVE-2020-28014)

  - Exim 4 before 4.94.2 has Improper Neutralization of Line Delimiters. Local users can alter the behavior of
    root processes because a recipient address can have a newline character. (CVE-2020-28015)

  - Exim 4 before 4.94.2 allows an off-by-two Out-of-bounds Write because -F '' is mishandled by
    parse_fix_phrase. (CVE-2020-28016)

  - Exim 4 before 4.94.2 allows Integer Overflow to Buffer Overflow in receive_add_recipient via an e-mail
    message with fifty million recipients. NOTE: remote exploitation may be difficult because of resource
    consumption. (CVE-2020-28017)

  - Exim 4 before 4.92 allows Integer Overflow to Buffer Overflow, in which an unauthenticated remote attacker
    can execute arbitrary code by leveraging the mishandling of continuation lines during header-length
    restriction. (CVE-2020-28020)

  - Exim 4 before 4.94.2 has Improper Restriction of Write Operations within the Bounds of a Memory Buffer.
    This occurs when processing name=value pairs within MAIL FROM and RCPT TO commands. (CVE-2020-28022)

  - Exim 4 before 4.94.2 allows Buffer Underwrite that may result in unauthenticated remote attackers
    executing arbitrary commands, because smtp_ungetc was only intended to push back characters, but can
    actually push back non-character error codes such as EOF. (CVE-2020-28024)

  - Exim 4 before 4.94.2 allows Out-of-bounds Read because pdkim_finish_bodyhash does not validate the
    relationship between sig->bodyhash.len and b->bh.len; thus, a crafted DKIM-Signature header might lead to
    a leak of sensitive information from process memory. (CVE-2020-28025)

  - Exim 4 before 4.94.2 has Improper Neutralization of Line Delimiters, relevant in non-default
    configurations that enable Delivery Status Notification (DSN). Certain uses of ORCPT= can place a newline
    into a spool header file, and indirectly allow unauthenticated remote attackers to execute arbitrary
    commands as root. (CVE-2020-28026)

  - Exim 4 before 4.94.2 has Execution with Unnecessary Privileges. By leveraging a delete_pid_file race
    condition, a local user can delete arbitrary files as root. This involves the -oP and -oPX options.
    (CVE-2021-27216)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4934-2");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-28026");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:exim4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:exim4-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:exim4-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:exim4-daemon-heavy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:exim4-daemon-light");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:exim4-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:eximon4");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2021-2023 Canonical, Inc. / NASL script (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('ubuntu.inc');
include('misc_func.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
release = chomp(release);
if (! preg(pattern:"^(16\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


pkgs = [
    {'osver': '16.04', 'pkgname': 'exim4', 'pkgver': '4.86.2-2ubuntu2.6+esm1'},
    {'osver': '16.04', 'pkgname': 'exim4-base', 'pkgver': '4.86.2-2ubuntu2.6+esm1'},
    {'osver': '16.04', 'pkgname': 'exim4-config', 'pkgver': '4.86.2-2ubuntu2.6+esm1'},
    {'osver': '16.04', 'pkgname': 'exim4-daemon-heavy', 'pkgver': '4.86.2-2ubuntu2.6+esm1'},
    {'osver': '16.04', 'pkgname': 'exim4-daemon-light', 'pkgver': '4.86.2-2ubuntu2.6+esm1'},
    {'osver': '16.04', 'pkgname': 'exim4-dev', 'pkgver': '4.86.2-2ubuntu2.6+esm1'},
    {'osver': '16.04', 'pkgname': 'eximon4', 'pkgver': '4.86.2-2ubuntu2.6+esm1'}
];

flag = 0;
foreach package_array ( pkgs ) {
  osver = NULL;
  pkgname = NULL;
  pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'exim4 / exim4-base / exim4-config / exim4-daemon-heavy / etc');
}
