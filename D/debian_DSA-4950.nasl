#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-4950. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152270);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id(
    "CVE-2019-10156",
    "CVE-2019-10206",
    "CVE-2019-14846",
    "CVE-2019-14864",
    "CVE-2019-14904",
    "CVE-2020-1733",
    "CVE-2020-1735",
    "CVE-2020-1739",
    "CVE-2020-1740",
    "CVE-2020-1746",
    "CVE-2020-1753",
    "CVE-2020-10684",
    "CVE-2020-10685",
    "CVE-2020-10729",
    "CVE-2020-14330",
    "CVE-2020-14332",
    "CVE-2020-14365",
    "CVE-2021-20228"
  );
  script_xref(name:"IAVB", value:"2020-B-0016-S");
  script_xref(name:"IAVB", value:"2020-B-0073-S");
  script_xref(name:"IAVB", value:"2019-B-0092-S");
  script_xref(name:"IAVB", value:"2021-B-0013-S");

  script_name(english:"Debian DSA-4950-1 : ansible - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-4950 advisory.

  - A flaw was discovered in the way Ansible templating was implemented in versions before 2.6.18, 2.7.12 and
    2.8.2, causing the possibility of information disclosure through unexpected variable substitution. By
    taking advantage of unintended variable substitution the content of any variable may be disclosed.
    (CVE-2019-10156)

  - ansible-playbook -k and ansible cli tools, all versions 2.8.x before 2.8.4, all 2.7.x before 2.7.13 and
    all 2.6.x before 2.6.19, prompt passwords by expanding them from templates as they could contain special
    characters. Passwords should be wrapped to prevent templates trigger and exposing them. (CVE-2019-10206)

  - In Ansible, all Ansible Engine versions up to ansible-engine 2.8.5, ansible-engine 2.7.13, ansible-engine
    2.6.19, were logging at the DEBUG level which lead to a disclosure of credentials if a plugin used a
    library that logged credentials at the DEBUG level. This flaw does not affect Ansible modules, as those
    are executed in a separate process. (CVE-2019-14846)

  - Ansible, versions 2.9.x before 2.9.1, 2.8.x before 2.8.7 and Ansible versions 2.7.x before 2.7.15, is not
    respecting the flag no_log set it to True when Sumologic and Splunk callback plugins are used send tasks
    results events to collectors. This would discloses and collects any sensitive data. (CVE-2019-14864)

  - A flaw was found in the solaris_zone module from the Ansible Community modules. When setting the name for
    the zone on the Solaris host, the zone name is checked by listing the process with the 'ps' bare command
    on the remote machine. An attacker could take advantage of this flaw by crafting the name of the zone and
    executing arbitrary commands in the remote host. Ansible Engine 2.7.15, 2.8.7, and 2.9.2 as well as
    previous versions are affected. (CVE-2019-14904)

  - A flaw was found in Ansible Engine, all versions 2.7.x, 2.8.x and 2.9.x prior to 2.7.17, 2.8.9 and 2.9.6
    respectively, when using ansible_facts as a subkey of itself and promoting it to a variable when inject is
    enabled, overwriting the ansible_facts after the clean. An attacker could take advantage of this by
    altering the ansible_facts, such as ansible_hosts, users and any other key data which would lead into
    privilege escalation or code injection. (CVE-2020-10684)

  - A flaw was found in Ansible Engine affecting Ansible Engine versions 2.7.x before 2.7.17 and 2.8.x before
    2.8.11 and 2.9.x before 2.9.7 as well as Ansible Tower before and including versions 3.4.5 and 3.5.5 and
    3.6.3 when using modules which decrypts vault files such as assemble, script, unarchive, win_copy, aws_s3
    or copy modules. The temporary directory is created in /tmp leaves the s ts unencrypted. On Operating
    Systems which /tmp is not a tmpfs but part of the root partition, the directory is only cleared on boot
    and the decryp emains when the host is switched off. The system will be vulnerable when the system is not
    running. So decrypted data must be cleared as soon as possible and the data which normally is encrypted
    ble. (CVE-2020-10685)

  - A flaw was found in the use of insufficiently random values in Ansible. Two random password lookups of the
    same length generate the equal value as the template caching action for the same file since no re-
    evaluation happens. The highest threat from this vulnerability would be that all passwords are exposed at
    once for the file. This flaw affects Ansible Engine versions before 2.9.6. (CVE-2020-10729)

  - An Improper Output Neutralization for Logs flaw was found in Ansible when using the uri module, where
    sensitive data is exposed to content and json output. This flaw allows an attacker to access the logs or
    outputs of performed tasks to read keys used in playbooks from other users within the uri module. The
    highest threat from this vulnerability is to data confidentiality. (CVE-2020-14330)

  - A flaw was found in the Ansible Engine when using module_args. Tasks executed with check mode (--check-
    mode) do not properly neutralize sensitive data exposed in the event data. This flaw allows unauthorized
    users to read this data. The highest threat from this vulnerability is to confidentiality.
    (CVE-2020-14332)

  - A flaw was found in the Ansible Engine, in ansible-engine 2.8.x before 2.8.15 and ansible-engine 2.9.x
    before 2.9.13, when installing packages using the dnf module. GPG signatures are ignored during
    installation even when disable_gpg_check is set to False, which is the default behavior. This flaw leads
    to malicious packages being installed on the system and arbitrary code executed via package installation
    scripts. The highest threat from this vulnerability is to integrity and system availability.
    (CVE-2020-14365)

  - A race condition flaw was found in Ansible Engine 2.7.17 and prior, 2.8.9 and prior, 2.9.6 and prior when
    running a playbook with an unprivileged become user. When Ansible needs to run a module with become user,
    the temporary directory is created in /var/tmp. This directory is created with umask 77 && mkdir -p
    ; this operation does not fail if the directory already exists and is owned by another user. An
    attacker could take advantage to gain control of the become user as the target directory can be retrieved
    by iterating '/proc//cmdline'. (CVE-2020-1733)

  - A flaw was found in the Ansible Engine when the fetch module is used. An attacker could intercept the
    module, inject a new path, and then choose a new destination path on the controller node. All versions in
    2.7.x, 2.8.x and 2.9.x branches are believed to be vulnerable. (CVE-2020-1735)

  - A flaw was found in Ansible 2.7.16 and prior, 2.8.8 and prior, and 2.9.5 and prior when a password is set
    with the argument password of svn module, it is used on svn command line, disclosing to other users
    within the same node. An attacker could take advantage by reading the cmdline file from that particular
    PID on the procfs. (CVE-2020-1739)

  - A flaw was found in Ansible Engine when using Ansible Vault for editing encrypted files. When a user
    executes ansible-vault edit, another user on the same computer can read the old and new secret, as it is
    created in a temporary file with mkstemp and the returned file descriptor is closed and the method
    write_data is called to write the existing secret in the file. This method will delete the file before
    recreating it insecurely. All versions in 2.7.x, 2.8.x and 2.9.x branches are believed to be vulnerable.
    (CVE-2020-1740)

  - A flaw was found in the Ansible Engine affecting Ansible Engine versions 2.7.x before 2.7.17 and 2.8.x
    before 2.8.11 and 2.9.x before 2.9.7 as well as Ansible Tower before and including versions 3.4.5 and
    3.5.5 and 3.6.3 when the ldap_attr and ldap_entry community modules are used. The issue discloses the LDAP
    bind password to stdout or a log file if a playbook task is written using the bind_pw in the parameters
    field. The highest threat from this vulnerability is data confidentiality. (CVE-2020-1746)

  - A security flaw was found in Ansible Engine, all Ansible 2.7.x versions prior to 2.7.17, all Ansible 2.8.x
    versions prior to 2.8.11 and all Ansible 2.9.x versions prior to 2.9.7, when managing kubernetes using the
    k8s module. Sensitive parameters such as passwords and tokens are passed to kubectl from the command line,
    not using an environment variable or an input configuration file. This will disclose passwords and tokens
    from process list and no_log directive from debug module would not have any effect making these secrets
    being disclosed on stdout and log files. (CVE-2020-1753)

  - A flaw was found in the Ansible Engine 2.9.18, where sensitive info is not masked by default and is not
    protected by the no_log feature when using the sub-option feature of the basic.py module. This flaw allows
    an attacker to obtain sensitive information. The highest threat from this vulnerability is to
    confidentiality. (CVE-2021-20228)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/ansible");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2021/dsa-4950");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-10156");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-10206");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-14846");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-14864");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-14904");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-10684");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-10685");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-10729");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-14330");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-14332");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-14365");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-1733");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-1735");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-1739");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-1740");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-1746");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-1753");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-20228");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/ansible");
  script_set_attribute(attribute:"solution", value:
"Upgrade the ansible packages.

For the stable distribution (buster), these problems have been fixed in version 2.7.7+dfsg-1+deb10u1.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14365");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-14846");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ansible");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ansible-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
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

release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
release = chomp(release);
if (! preg(pattern:"^(10)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + release);
cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

pkgs = [
    {'release': '10.0', 'prefix': 'ansible', 'reference': '2.7.7+dfsg-1+deb10u1'},
    {'release': '10.0', 'prefix': 'ansible-doc', 'reference': '2.7.7+dfsg-1+deb10u1'}
];

flag = 0;
foreach package_array ( pkgs ) {
  release = NULL;
  prefix = NULL;
  reference = NULL;
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
    severity   : SECURITY_WARNING,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ansible / ansible-doc');
}
