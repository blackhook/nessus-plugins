#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2021:14650-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150586);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/21");

  script_cve_id(
    "CVE-2020-28243",
    "CVE-2020-28972",
    "CVE-2020-35662",
    "CVE-2021-3144",
    "CVE-2021-3148",
    "CVE-2021-3197",
    "CVE-2021-25281",
    "CVE-2021-25282",
    "CVE-2021-25283",
    "CVE-2021-25284"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2021:14650-1");
  script_xref(name:"IAVA", value:"2021-A-0112-S");

  script_name(english:"SUSE SLES11 Security Update : salt (SUSE-SU-2021:14650-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES11 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2021:14650-1 advisory.

  - An issue was discovered in SaltStack Salt before 3002.5. The minion's restartcheck is vulnerable to
    command injection via a crafted process name. This allows for a local privilege escalation by any user
    able to create a files on the minion in a non-blacklisted directory. (CVE-2020-28243)

  - In SaltStack Salt before 3002.5, authentication to VMware vcenter, vsphere, and esxi servers (in the
    vmware.py files) does not always validate the SSL/TLS certificate. (CVE-2020-28972)

  - In SaltStack Salt before 3002.5, when authenticating to services using certain modules, the SSL
    certificate is not always validated. (CVE-2020-35662)

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

  - An issue was discovered in SaltStack Salt before 3002.5. The salt-api's ssh client is vulnerable to a
    shell injection by including ProxyCommand in an argument, or via ssh_options provided in an API request.
    (CVE-2021-3197)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181550");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181556");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181557");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181558");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181559");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181560");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181561");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181562");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181563");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181564");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181565");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182740");
  # https://lists.suse.com/pipermail/sle-security-updates/2021-February/008380.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e8f71505");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-28243");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-28972");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-35662");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-25281");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-25282");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-25283");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-25284");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3144");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3148");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3197");
  script_set_attribute(attribute:"solution", value:
"Update the affected salt, salt-doc and / or salt-minion packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3197");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SaltStack Salt API Unauthenticated RCE through wheel_async client');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:salt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:salt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:salt-minion");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES11', 'SUSE ' + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE ' + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! preg(pattern:"^(3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP3/4", os_ver + " SP" + sp);

pkgs = [
    {'reference':'salt-2016.11.10-43.69', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'salt-doc-2016.11.10-43.69', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'salt-minion-2016.11.10-43.69', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'salt-2016.11.10-43.69', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'salt-doc-2016.11.10-43.69', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'salt-minion-2016.11.10-43.69', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'salt-2016.11.10-43.69', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'salt-doc-2016.11.10-43.69', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'salt-minion-2016.11.10-43.69', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'salt-2016.11.10-43.69', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'salt-doc-2016.11.10-43.69', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'salt-minion-2016.11.10-43.69', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  sp = NULL;
  cpu = NULL;
  exists_check = NULL;
  rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release && exists_check) {
    if (rpm_exists(release:release, rpm:exists_check) && rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
  else if (reference && release) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'salt / salt-doc / salt-minion');
}
