#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5011. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155634);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/01");

  script_cve_id(
    "CVE-2020-28243",
    "CVE-2020-28972",
    "CVE-2020-35662",
    "CVE-2021-3144",
    "CVE-2021-3148",
    "CVE-2021-3197",
    "CVE-2021-21996",
    "CVE-2021-25281",
    "CVE-2021-25282",
    "CVE-2021-25283",
    "CVE-2021-25284",
    "CVE-2021-31607"
  );
  script_xref(name:"IAVA", value:"2021-A-0112-S");
  script_xref(name:"IAVA", value:"2021-A-0524-S");

  script_name(english:"Debian DSA-5011-1 : salt - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 / 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5011 advisory.

  - An issue was discovered in SaltStack Salt before 3002.5. The minion's restartcheck is vulnerable to
    command injection via a crafted process name. This allows for a local privilege escalation by any user
    able to create a files on the minion in a non-blacklisted directory. (CVE-2020-28243)

  - In SaltStack Salt before 3002.5, authentication to VMware vcenter, vsphere, and esxi servers (in the
    vmware.py files) does not always validate the SSL/TLS certificate. (CVE-2020-28972)

  - In SaltStack Salt before 3002.5, when authenticating to services using certain modules, the SSL
    certificate is not always validated. (CVE-2020-35662)

  - An issue was discovered in SaltStack Salt before 3003.3. A user who has control of the source, and
    source_hash URLs can gain full file system access as root on a salt minion. (CVE-2021-21996)

  - An issue was discovered in through SaltStack Salt before 3002.5. salt-api does not honor eauth credentials
    for the wheel_async client. Thus, an attacker can remotely run any wheel modules on the master.
    (CVE-2021-25281)

  - An issue was discovered in through SaltStack Salt before 3002.5. The salt.wheel.pillar_roots.write method
    is vulnerable to directory traversal. (CVE-2021-25282)

  - An issue was discovered in through SaltStack Salt before 3002.5. The jinja renderer does not protect
    against server side template injection attacks. (CVE-2021-25283)

  - An issue was discovered in through SaltStack Salt before 3002.5. salt.modules.cmdmod can log credentials
    to the info or error log level. (CVE-2021-25284)

  - In SaltStack Salt before 3002.5, eauth tokens can be used once after expiration. (They might be used to
    run command against the salt master or minions.) (CVE-2021-3144)

  - An issue was discovered in SaltStack Salt before 3002.5. Sending crafted web requests to the Salt API can
    result in salt.utils.thin.gen_thin() command injection because of different handling of single versus
    double quotes. This is related to salt/utils/thin.py. (CVE-2021-3148)

  - In SaltStack Salt 2016.9 through 3002.6, a command injection vulnerability exists in the snapper module
    that allows for local privilege escalation on a minion. The attack requires that a file is created with a
    pathname that is backed up by snapper, and that the master calls the snapper.diff function (which executes
    popen unsafely). (CVE-2021-31607)

  - An issue was discovered in SaltStack Salt before 3002.5. The salt-api's ssh client is vulnerable to a
    shell injection by including ProxyCommand in an argument, or via ssh_options provided in an API request.
    (CVE-2021-3197)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=983632");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/salt");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2021/dsa-5011");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-28243");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-28972");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-35662");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-21996");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-25281");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-25282");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-25283");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-25284");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3144");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3148");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-31607");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3197");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/salt");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/salt");
  script_set_attribute(attribute:"solution", value:
"Upgrade the salt packages.

For the stable distribution (bullseye), this problem has been fixed in version 3002.6+dfsg1-4+deb11u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3197");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SaltStack Salt API Unauthenticated RCE through wheel_async client');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:salt-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:salt-cloud");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:salt-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:salt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:salt-master");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:salt-minion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:salt-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:salt-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:salt-syndic");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(10)\.[0-9]+|^(11)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 10.0 / 11.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'salt-api', 'reference': '2018.3.4+dfsg1-6+deb10u3'},
    {'release': '10.0', 'prefix': 'salt-cloud', 'reference': '2018.3.4+dfsg1-6+deb10u3'},
    {'release': '10.0', 'prefix': 'salt-common', 'reference': '2018.3.4+dfsg1-6+deb10u3'},
    {'release': '10.0', 'prefix': 'salt-doc', 'reference': '2018.3.4+dfsg1-6+deb10u3'},
    {'release': '10.0', 'prefix': 'salt-master', 'reference': '2018.3.4+dfsg1-6+deb10u3'},
    {'release': '10.0', 'prefix': 'salt-minion', 'reference': '2018.3.4+dfsg1-6+deb10u3'},
    {'release': '10.0', 'prefix': 'salt-proxy', 'reference': '2018.3.4+dfsg1-6+deb10u3'},
    {'release': '10.0', 'prefix': 'salt-ssh', 'reference': '2018.3.4+dfsg1-6+deb10u3'},
    {'release': '10.0', 'prefix': 'salt-syndic', 'reference': '2018.3.4+dfsg1-6+deb10u3'},
    {'release': '11.0', 'prefix': 'salt-api', 'reference': '3002.6+dfsg1-4+deb11u1'},
    {'release': '11.0', 'prefix': 'salt-cloud', 'reference': '3002.6+dfsg1-4+deb11u1'},
    {'release': '11.0', 'prefix': 'salt-common', 'reference': '3002.6+dfsg1-4+deb11u1'},
    {'release': '11.0', 'prefix': 'salt-doc', 'reference': '3002.6+dfsg1-4+deb11u1'},
    {'release': '11.0', 'prefix': 'salt-master', 'reference': '3002.6+dfsg1-4+deb11u1'},
    {'release': '11.0', 'prefix': 'salt-minion', 'reference': '3002.6+dfsg1-4+deb11u1'},
    {'release': '11.0', 'prefix': 'salt-proxy', 'reference': '3002.6+dfsg1-4+deb11u1'},
    {'release': '11.0', 'prefix': 'salt-ssh', 'reference': '3002.6+dfsg1-4+deb11u1'},
    {'release': '11.0', 'prefix': 'salt-syndic', 'reference': '3002.6+dfsg1-4+deb11u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'salt-api / salt-cloud / salt-common / salt-doc / salt-master / etc');
}
