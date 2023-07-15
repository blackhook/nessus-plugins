#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151324);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/06");

  script_cve_id(
    "CVE-2016-1246",
    "CVE-2016-1249",
    "CVE-2017-10788",
    "CVE-2017-10789"
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.2.0 : perl-DBD-MySQL (EulerOS-SA-2021-2072)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the perl-DBD-MySQL package installed,
the EulerOS Virtualization for ARM 64 installation on the remote host
is affected by the following vulnerabilities :

  - The DBD::mysql module through 4.043 for Perl uses the
    mysql_ssl=1 setting to mean that SSL is optional (even
    though this setting's documentation has a 'your
    communication with the server will be encrypted'
    statement), which allows man-in-the-middle attackers to
    spoof servers via a cleartext-downgrade attack, a
    related issue to CVE-2015-3152.(CVE-2017-10789)

  - The DBD::mysql module before 4.039 for Perl, when using
    server-side prepared statement support, allows
    attackers to cause a denial of service (out-of-bounds
    read) via vectors involving an unaligned number of
    placeholders in WHERE condition and output fields in
    SELECT expression.(CVE-2016-1249)

  - The DBD::mysql module through 4.043 for Perl allows
    remote attackers to cause a denial of service
    (use-after-free and application crash) or possibly have
    unspecified other impact by triggering (1) certain
    error responses from a MySQL server or (2) a loss of a
    network connection to a MySQL server. The
    use-after-free defect was introduced by relying on
    incorrect Oracle mysql_stmt_close documentation and
    code examples.(CVE-2017-10788)

  - Buffer overflow in the DBD::mysql module before 4.037
    for Perl allows context-dependent attackers to cause a
    denial of service (crash) via vectors related to an
    error message.(CVE-2016-1246)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2072
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?62ca20d9");
  script_set_attribute(attribute:"solution", value:
"Update the affected perl-DBD-MySQL packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perl-DBD-MySQL");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.2.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.2.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["perl-DBD-MySQL-4.023-6.h2"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "perl-DBD-MySQL");
}
