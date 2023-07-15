#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0036. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127206);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/19");

  script_cve_id(
    "CVE-2006-0225",
    "CVE-2006-4924",
    "CVE-2006-5051",
    "CVE-2006-5794",
    "CVE-2007-3102",
    "CVE-2010-4755",
    "CVE-2010-5107",
    "CVE-2014-2532"
  );

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : openssh Multiple Vulnerabilities (NS-SA-2019-0036)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has openssh packages installed that are affected
by multiple vulnerabilities:

  - scp in OpenSSH 4.2p1 allows attackers to execute
    arbitrary commands via filenames that contain shell
    metacharacters or spaces, which are expanded twice.
    (CVE-2006-0225)

  - sshd in OpenSSH before 4.4, when using the version 1 SSH
    protocol, allows remote attackers to cause a denial of
    service (CPU consumption) via an SSH packet that
    contains duplicate blocks, which is not properly handled
    by the CRC compensation attack detector. (CVE-2006-4924)

  - Signal handler race condition in OpenSSH before 4.4
    allows remote attackers to cause a denial of service
    (crash), and possibly execute arbitrary code if GSSAPI
    authentication is enabled, via unspecified vectors that
    lead to a double-free. (CVE-2006-5051)

  - Unspecified vulnerability in the sshd Privilege
    Separation Monitor in OpenSSH before 4.5 causes weaker
    verification that authentication has been successful,
    which might allow attackers to bypass authentication.
    NOTE: as of 20061108, it is believed that this issue is
    only exploitable by leveraging vulnerabilities in the
    unprivileged process, which are not known to exist.
    (CVE-2006-5794)

  - Unspecified vulnerability in the
    linux_audit_record_event function in OpenSSH 4.3p2, as
    used on Fedora Core 6 and possibly other systems, allows
    remote attackers to write arbitrary characters to an
    audit log via a crafted username. NOTE: some of these
    details are obtained from third party information.
    (CVE-2007-3102)

  - The (1) remote_glob function in sftp-glob.c and the (2)
    process_put function in sftp.c in OpenSSH 5.8 and
    earlier, as used in FreeBSD 7.3 and 8.1, NetBSD 5.0.2,
    OpenBSD 4.7, and other products, allow remote
    authenticated users to cause a denial of service (CPU
    and memory consumption) via crafted glob expressions
    that do not match any pathnames, as demonstrated by glob
    expressions in SSH_FXP_STAT requests to an sftp daemon,
    a different vulnerability than CVE-2010-2632.
    (CVE-2010-4755)

  - The default configuration of OpenSSH through 6.1
    enforces a fixed time limit between establishing a TCP
    connection and completing a login, which makes it easier
    for remote attackers to cause a denial of service
    (connection-slot exhaustion) by periodically making many
    new TCP connections. (CVE-2010-5107)

  - It was found that OpenSSH did not properly handle
    certain AcceptEnv parameter values with wildcard
    characters. A remote attacker could use this flaw to
    bypass intended environment variable restrictions.
    (CVE-2014-2532)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0036");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL openssh packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2006-5051");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2014-2532");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(362, 399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/01/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    "openssh-7.9p1-1.el7.cgslv5.0.2.gc747ef6",
    "openssh-askpass-7.9p1-1.el7.cgslv5.0.2.gc747ef6",
    "openssh-cavs-7.9p1-1.el7.cgslv5.0.2.gc747ef6",
    "openssh-clients-7.9p1-1.el7.cgslv5.0.2.gc747ef6",
    "openssh-debuginfo-7.9p1-1.el7.cgslv5.0.2.gc747ef6",
    "openssh-keycat-7.9p1-1.el7.cgslv5.0.2.gc747ef6",
    "openssh-ldap-7.9p1-1.el7.cgslv5.0.2.gc747ef6",
    "openssh-server-7.9p1-1.el7.cgslv5.0.2.gc747ef6",
    "pam_ssh_agent_auth-0.10.3-6.1.el7.cgslv5.0.2.gc747ef6"
  ],
  "CGSL MAIN 5.04": [
    "openssh-7.9p1-1.el7.cgslv5.0.2.gc747ef6",
    "openssh-askpass-7.9p1-1.el7.cgslv5.0.2.gc747ef6",
    "openssh-cavs-7.9p1-1.el7.cgslv5.0.2.gc747ef6",
    "openssh-clients-7.9p1-1.el7.cgslv5.0.2.gc747ef6",
    "openssh-debuginfo-7.9p1-1.el7.cgslv5.0.2.gc747ef6",
    "openssh-keycat-7.9p1-1.el7.cgslv5.0.2.gc747ef6",
    "openssh-ldap-7.9p1-1.el7.cgslv5.0.2.gc747ef6",
    "openssh-server-7.9p1-1.el7.cgslv5.0.2.gc747ef6",
    "pam_ssh_agent_auth-0.10.3-6.1.el7.cgslv5.0.2.gc747ef6"
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssh");
}
