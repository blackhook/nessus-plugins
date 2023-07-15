#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2022:0743-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158742);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/09");

  script_cve_id("CVE-2022-24407");

  script_name(english:"openSUSE 15 Security Update : cyrus-sasl (openSUSE-SU-2022:0743-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by a vulnerability as referenced in the
openSUSE-SU-2022:0743-1 advisory.

  - In Cyrus SASL 2.1.17 through 2.1.27 before 2.1.28, plugins/sql.c does not escape the password for a SQL
    INSERT or UPDATE statement. (CVE-2022-24407)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194265");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196036");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/BPABQLPWLWVSDVE54YNNZUHMKWEV6F3X/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ea436217");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-24407");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24407");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cyrus-sasl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cyrus-sasl-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cyrus-sasl-bdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cyrus-sasl-bdb-crammd5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cyrus-sasl-bdb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cyrus-sasl-bdb-digestmd5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cyrus-sasl-bdb-gs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cyrus-sasl-bdb-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cyrus-sasl-bdb-ntlm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cyrus-sasl-bdb-otp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cyrus-sasl-bdb-plain");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cyrus-sasl-bdb-scram");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cyrus-sasl-crammd5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cyrus-sasl-crammd5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cyrus-sasl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cyrus-sasl-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cyrus-sasl-digestmd5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cyrus-sasl-digestmd5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cyrus-sasl-gs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cyrus-sasl-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cyrus-sasl-gssapi-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cyrus-sasl-ldap-auxprop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cyrus-sasl-ldap-auxprop-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cyrus-sasl-ldap-auxprop-bdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cyrus-sasl-ntlm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cyrus-sasl-otp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cyrus-sasl-otp-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cyrus-sasl-plain");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cyrus-sasl-plain-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cyrus-sasl-saslauthd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cyrus-sasl-saslauthd-bdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cyrus-sasl-scram");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cyrus-sasl-sqlauxprop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cyrus-sasl-sqlauxprop-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cyrus-sasl-sqlauxprop-bdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsasl2-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsasl2-3-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'cyrus-sasl-2.1.27-150300.4.6.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-32bit-2.1.27-150300.4.6.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-bdb-2.1.27-150300.4.6.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-bdb-crammd5-2.1.27-150300.4.6.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-bdb-devel-2.1.27-150300.4.6.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-bdb-digestmd5-2.1.27-150300.4.6.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-bdb-gs2-2.1.27-150300.4.6.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-bdb-gssapi-2.1.27-150300.4.6.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-bdb-ntlm-2.1.27-150300.4.6.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-bdb-otp-2.1.27-150300.4.6.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-bdb-plain-2.1.27-150300.4.6.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-bdb-scram-2.1.27-150300.4.6.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-crammd5-2.1.27-150300.4.6.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-crammd5-32bit-2.1.27-150300.4.6.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-devel-2.1.27-150300.4.6.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-devel-32bit-2.1.27-150300.4.6.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-digestmd5-2.1.27-150300.4.6.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-digestmd5-32bit-2.1.27-150300.4.6.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-gs2-2.1.27-150300.4.6.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-gssapi-2.1.27-150300.4.6.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-gssapi-32bit-2.1.27-150300.4.6.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-ldap-auxprop-2.1.27-150300.4.6.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-ldap-auxprop-32bit-2.1.27-150300.4.6.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-ldap-auxprop-bdb-2.1.27-150300.4.6.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-ntlm-2.1.27-150300.4.6.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-otp-2.1.27-150300.4.6.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-otp-32bit-2.1.27-150300.4.6.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-plain-2.1.27-150300.4.6.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-plain-32bit-2.1.27-150300.4.6.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-saslauthd-2.1.27-150300.4.6.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-saslauthd-bdb-2.1.27-150300.4.6.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-scram-2.1.27-150300.4.6.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-sqlauxprop-2.1.27-150300.4.6.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-sqlauxprop-32bit-2.1.27-150300.4.6.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-sqlauxprop-bdb-2.1.27-150300.4.6.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsasl2-3-2.1.27-150300.4.6.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsasl2-3-32bit-2.1.27-150300.4.6.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cyrus-sasl / cyrus-sasl-32bit / cyrus-sasl-bdb / etc');
}
