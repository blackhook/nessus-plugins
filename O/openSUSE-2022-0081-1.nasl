#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2022:0081-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159049);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/03");

  script_cve_id(
    "CVE-2018-10875",
    "CVE-2018-16837",
    "CVE-2019-10156",
    "CVE-2019-14846",
    "CVE-2019-14904",
    "CVE-2019-14905",
    "CVE-2020-1733",
    "CVE-2020-1734",
    "CVE-2020-1735",
    "CVE-2020-1736",
    "CVE-2020-1737",
    "CVE-2020-1738",
    "CVE-2020-1739",
    "CVE-2020-1740",
    "CVE-2020-1746",
    "CVE-2020-1753",
    "CVE-2020-10684",
    "CVE-2020-10685",
    "CVE-2020-10691",
    "CVE-2020-10729",
    "CVE-2020-14330",
    "CVE-2020-14332",
    "CVE-2021-20178",
    "CVE-2021-20180",
    "CVE-2021-20191",
    "CVE-2021-20228"
  );
  script_xref(name:"IAVB", value:"2019-B-0092-S");
  script_xref(name:"IAVB", value:"2020-B-0016-S");
  script_xref(name:"IAVB", value:"2021-B-0013-S");

  script_name(english:"openSUSE 15 Security Update : ansible (openSUSE-SU-2022:0081-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2022:0081-1 advisory.

  - A flaw was found in ansible. ansible.cfg is read from the current working directory which can be altered
    to make it point to a plugin or a module path under the control of an attacker, thus allowing the attacker
    to execute arbitrary code. (CVE-2018-10875)

  - Ansible User module leaks any data which is passed on as a parameter to ssh-keygen. This could lean in
    undesirable situations such as passphrases credentials passed as a parameter for the ssh-keygen
    executable. Showing those credentials in clear text form for every user which have access just to the
    process list. (CVE-2018-16837)

  - A flaw was discovered in the way Ansible templating was implemented in versions before 2.6.18, 2.7.12 and
    2.8.2, causing the possibility of information disclosure through unexpected variable substitution. By
    taking advantage of unintended variable substitution the content of any variable may be disclosed.
    (CVE-2019-10156)

  - In Ansible, all Ansible Engine versions up to ansible-engine 2.8.5, ansible-engine 2.7.13, ansible-engine
    2.6.19, were logging at the DEBUG level which lead to a disclosure of credentials if a plugin used a
    library that logged credentials at the DEBUG level. This flaw does not affect Ansible modules, as those
    are executed in a separate process. (CVE-2019-14846)

  - A flaw was found in the solaris_zone module from the Ansible Community modules. When setting the name for
    the zone on the Solaris host, the zone name is checked by listing the process with the 'ps' bare command
    on the remote machine. An attacker could take advantage of this flaw by crafting the name of the zone and
    executing arbitrary commands in the remote host. Ansible Engine 2.7.15, 2.8.7, and 2.9.2 as well as
    previous versions are affected. (CVE-2019-14904)

  - A vulnerability was found in Ansible Engine versions 2.9.x before 2.9.3, 2.8.x before 2.8.8, 2.7.x before
    2.7.16 and earlier, where in Ansible's nxos_file_copy module can be used to copy files to a flash or
    bootflash on NXOS devices. Malicious code could craft the filename parameter to perform OS command
    injections. This could result in a loss of confidentiality of the system among other issues.
    (CVE-2019-14905)

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

  - An archive traversal flaw was found in all ansible-engine versions 2.9.x prior to 2.9.7, when running
    ansible-galaxy collection install. When extracting a collection .tar.gz file, the directory is created
    without sanitizing the filename. An attacker could take advantage to overwrite any file within the system.
    (CVE-2020-10691)

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

  - A race condition flaw was found in Ansible Engine 2.7.17 and prior, 2.8.9 and prior, 2.9.6 and prior when
    running a playbook with an unprivileged become user. When Ansible needs to run a module with become user,
    the temporary directory is created in /var/tmp. This directory is created with umask 77 && mkdir -p
    <dir>; this operation does not fail if the directory already exists and is owned by another user. An
    attacker could take advantage to gain control of the become user as the target directory can be retrieved
    by iterating '/proc/<pid>/cmdline'. (CVE-2020-1733)

  - A flaw was found in the pipe lookup plugin of ansible. Arbitrary commands can be run, when the pipe lookup
    plugin uses subprocess.Popen() with shell=True, by overwriting ansible facts and the variable is not
    escaped by quote plugin. An attacker could take advantage and run arbitrary commands by overwriting the
    ansible facts. (CVE-2020-1734)

  - A flaw was found in the Ansible Engine when the fetch module is used. An attacker could intercept the
    module, inject a new path, and then choose a new destination path on the controller node. All versions in
    2.7.x, 2.8.x and 2.9.x branches are believed to be vulnerable. (CVE-2020-1735)

  - A flaw was found in Ansible Engine when a file is moved using atomic_move primitive as the file mode
    cannot be specified. This sets the destination files world-readable if the destination file does not exist
    and if the file exists, the file could be changed to have less restrictive permissions before the move.
    This could lead to the disclosure of sensitive data. All versions in 2.7.x, 2.8.x and 2.9.x branches are
    believed to be vulnerable. (CVE-2020-1736)

  - A flaw was found in Ansible 2.7.17 and prior, 2.8.9 and prior, and 2.9.6 and prior when using the Extract-
    Zip function from the win_unzip module as the extracted file(s) are not checked if they belong to the
    destination folder. An attacker could take advantage of this flaw by crafting an archive anywhere in the
    file system, using a path traversal. This issue is fixed in 2.10. (CVE-2020-1737)

  - A flaw was found in Ansible Engine when the module package or service is used and the parameter 'use' is
    not specified. If a previous task is executed with a malicious user, the module sent can be selected by
    the attacker using the ansible facts file. All versions in 2.7.x, 2.8.x and 2.9.x branches are believed to
    be vulnerable. (CVE-2020-1738)

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

  - A flaw was found in ansible module where credentials are disclosed in the console log by default and not
    protected by the security feature when using the bitbucket_pipeline_variable module. This flaw allows an
    attacker to steal bitbucket_pipeline credentials. The highest threat from this vulnerability is to
    confidentiality. (CVE-2021-20178, CVE-2021-20180)

  - A flaw was found in ansible. Credentials, such as secrets, are being disclosed in console log by default
    and not protected by no_log feature when using those modules. An attacker can take advantage of this
    information to steal those credentials. The highest threat from this vulnerability is to data
    confidentiality. Versions before ansible 2.9.18 are affected. (CVE-2021-20191)

  - A flaw was found in the Ansible Engine 2.9.18, where sensitive info is not masked by default and is not
    protected by the no_log feature when using the sub-option feature of the basic.py module. This flaw allows
    an attacker to obtain sensitive information. The highest threat from this vulnerability is to
    confidentiality. (CVE-2021-20228)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1099808");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1112959");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1118896");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1126503");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1137528");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1157968");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1157969");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1164133");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1164134");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1164135");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1164136");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1164137");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1164138");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1164139");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1164140");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1165393");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1166389");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1167440");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1167532");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1167873");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1171162");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1174145");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1174302");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1180816");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1180942");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181119");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181935");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/D7KK2SNPNAB353QA6BU4SNJDQ3FXZOY5/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e770872f");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-10875");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-16837");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-10156");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-14846");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-14904");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-14905");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-10684");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-10685");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-10691");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-10729");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-14330");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-14332");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-1733");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-1734");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-1735");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-1736");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-1737");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-1738");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-1739");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-1740");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-1746");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-1753");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-20178");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-20180");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-20191");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-20228");
  script_set_attribute(attribute:"solution", value:
"Update the affected ansible and / or ansible-test packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14904");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-1737");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ansible");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ansible-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/SuSE/release');
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
os_ver = os_ver[1];
if (release !~ "^(SUSE15\.3)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.3', release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + os_ver, cpu);

var pkgs = [
    {'reference':'ansible-2.9.21-bp153.2.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ansible-test-2.9.21-bp153.2.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var cpu = NULL;
  var rpm_spec_vers_cmp = NULL;
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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ansible / ansible-test');
}
