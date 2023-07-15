#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0198. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(129937);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id(
    "CVE-2007-0003",
    "CVE-2009-0579",
    "CVE-2010-3316",
    "CVE-2010-3435",
    "CVE-2010-3853",
    "CVE-2013-7041",
    "CVE-2014-2583"
  );

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : pam Multiple Vulnerabilities (NS-SA-2019-0198)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has pam packages installed that are affected by
multiple vulnerabilities:

  - pam_unix.so in Linux-PAM 0.99.7.0 allows context-
    dependent attackers to log into accounts whose password
    hash, as stored in /etc/passwd or /etc/shadow, has only
    two characters. (CVE-2007-0003)

  - Linux-PAM before 1.0.4 does not enforce the minimum
    password age (MINDAYS) as specified in /etc/shadow,
    which allows local users to bypass intended security
    policy and change their passwords sooner than specified.
    (CVE-2009-0579)

  - The run_coprocess function in pam_xauth.c in the
    pam_xauth module in Linux-PAM (aka pam) before 1.1.2
    does not check the return values of the setuid, setgid,
    and setgroups system calls, which might allow local
    users to read arbitrary files by executing a program
    that relies on the pam_xauth PAM check. (CVE-2010-3316)

  - The (1) pam_env and (2) pam_mail modules in Linux-PAM
    (aka pam) before 1.1.2 use root privileges during read
    access to files and directories that belong to arbitrary
    user accounts, which might allow local users to obtain
    sensitive information by leveraging this filesystem
    activity, as demonstrated by a symlink attack on the
    .pam_environment file in a user's home directory.
    (CVE-2010-3435)

  - pam_namespace.c in the pam_namespace module in Linux-PAM
    (aka pam) before 1.1.3 uses the environment of the
    invoking application or service during execution of the
    namespace.init script, which might allow local users to
    gain privileges by running a setuid program that relies
    on the pam_namespace PAM check, as demonstrated by the
    sudo program. (CVE-2010-3853)

  - The pam_userdb module for Pam uses a case-insensitive
    method to compare hashed passwords, which makes it
    easier for attackers to guess the password via a brute
    force attack. (CVE-2013-7041)

  - Multiple directory traversal vulnerabilities in
    pam_timestamp.c in the pam_timestamp module for Linux-
    PAM (aka pam) 1.1.8 allow local users to create
    arbitrary files or possibly bypass authentication via a
    .. (dot dot) in the (1) PAM_RUSER value to the get_ruser
    function or (2) PAM_TTY value to the check_tty function,
    which is used by the format_timestamp_name function.
    (CVE-2014-2583)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0198");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL pam packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2007-0003");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/01/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/ZTE-CGSL/release");
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, "NewStart Carrier Grade Server Linux");

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL CORE 5.04": [
    "pam-1.1.8-18.el7.cgslv5.0.3.g0dd876c.lite",
    "pam-debuginfo-1.1.8-18.el7.cgslv5.0.3.g0dd876c.lite",
    "pam-devel-1.1.8-18.el7.cgslv5.0.3.g0dd876c.lite",
    "pam-lang-1.1.8-18.el7.cgslv5.0.3.g0dd876c.lite"
  ],
  "CGSL MAIN 5.04": [
    "pam-1.1.8-18.el7.cgslv5.0.1.ga1d75e3",
    "pam-debuginfo-1.1.8-18.el7.cgslv5.0.1.ga1d75e3",
    "pam-devel-1.1.8-18.el7.cgslv5.0.1.ga1d75e3"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pam");
}
