#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##
# The descriptive text is (C) Scientific Linux.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158348);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/07");

  script_cve_id("CVE-2022-24407");
  script_xref(name:"RHSA", value:"RHSA-2022:0666");

  script_name(english:"Scientific Linux Security Update : cyrus-sasl on SL7.x i686/x86_64 (2022:0666)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Scientific Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Scientific Linux 7 host has packages installed that are affected by a vulnerability as referenced in the
SLSA-2022:0666-1 advisory.

  - cyrus-sasl: failure to properly escape SQL input allows an attacker to execute arbitrary SQL commands
    (CVE-2022-24407)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.scientificlinux.org/category/sl-errata/slsa-20220666-1");
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
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fermilab:scientific_linux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:cyrus-sasl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:cyrus-sasl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:cyrus-sasl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:cyrus-sasl-gs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:cyrus-sasl-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:cyrus-sasl-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:cyrus-sasl-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:cyrus-sasl-md5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:cyrus-sasl-ntlm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:cyrus-sasl-plain");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:cyrus-sasl-scram");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:cyrus-sasl-sql");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Scientific Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/RedHat/release');
if (isnull(release) || 'Scientific Linux' >!< release) audit(AUDIT_OS_NOT, 'Scientific Linux');
var os_ver = pregmatch(pattern: "Scientific Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Scientific Linux');
var os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Scientific Linux 7.x', 'Scientific Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Scientific Linux', cpu);

var pkgs = [
    {'reference':'cyrus-sasl-2.1.26-24.el7_9', 'cpu':'i686', 'release':'SL7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-2.1.26-24.el7_9', 'cpu':'x86_64', 'release':'SL7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-debuginfo-2.1.26-24.el7_9', 'cpu':'i686', 'release':'SL7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-debuginfo-2.1.26-24.el7_9', 'cpu':'x86_64', 'release':'SL7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-devel-2.1.26-24.el7_9', 'cpu':'i686', 'release':'SL7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-devel-2.1.26-24.el7_9', 'cpu':'x86_64', 'release':'SL7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-gs2-2.1.26-24.el7_9', 'cpu':'i686', 'release':'SL7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-gs2-2.1.26-24.el7_9', 'cpu':'x86_64', 'release':'SL7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-gssapi-2.1.26-24.el7_9', 'cpu':'i686', 'release':'SL7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-gssapi-2.1.26-24.el7_9', 'cpu':'x86_64', 'release':'SL7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-ldap-2.1.26-24.el7_9', 'cpu':'i686', 'release':'SL7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-ldap-2.1.26-24.el7_9', 'cpu':'x86_64', 'release':'SL7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-lib-2.1.26-24.el7_9', 'cpu':'i686', 'release':'SL7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-lib-2.1.26-24.el7_9', 'cpu':'x86_64', 'release':'SL7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-md5-2.1.26-24.el7_9', 'cpu':'i686', 'release':'SL7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-md5-2.1.26-24.el7_9', 'cpu':'x86_64', 'release':'SL7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-ntlm-2.1.26-24.el7_9', 'cpu':'i686', 'release':'SL7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-ntlm-2.1.26-24.el7_9', 'cpu':'x86_64', 'release':'SL7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-plain-2.1.26-24.el7_9', 'cpu':'i686', 'release':'SL7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-plain-2.1.26-24.el7_9', 'cpu':'x86_64', 'release':'SL7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-scram-2.1.26-24.el7_9', 'cpu':'i686', 'release':'SL7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-scram-2.1.26-24.el7_9', 'cpu':'x86_64', 'release':'SL7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-sql-2.1.26-24.el7_9', 'cpu':'i686', 'release':'SL7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-sql-2.1.26-24.el7_9', 'cpu':'x86_64', 'release':'SL7', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cyrus-sasl / cyrus-sasl-debuginfo / cyrus-sasl-devel / etc');
}
