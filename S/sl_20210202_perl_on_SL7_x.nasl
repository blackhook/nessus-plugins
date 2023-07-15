##
# (C) Tenable Network Security, Inc.
##
# The descriptive text is (C) Scientific Linux.
#

include('compat.inc');

if (description)
{
  script_id(146065);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2020-10543", "CVE-2020-10878", "CVE-2020-12723");
  script_xref(name:"RHSA", value:"RHSA-2021:0343");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Scientific Linux Security Update : perl on SL7.x i686/x86_64 (2021:0343)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Scientific Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Scientific Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SLSA-2021:0343-1 advisory.

  - perl: heap-based buffer overflow in regular expression compiler leads to DoS (CVE-2020-10543)

  - perl: corruption of intermediate language state of compiled regular expression due to integer overflow
    leads to DoS (CVE-2020-10878)

  - perl: corruption of intermediate language state of compiled regular expression due to recursive
    S_study_chunk() calls leads to DoS (CVE-2020-12723)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.scientificlinux.org/category/sl-errata/slsa-20210343-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-10878");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fermilab:scientific_linux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-CPAN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-ExtUtils-CBuilder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-ExtUtils-Embed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-ExtUtils-Install");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-IO-Zlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-Locale-Maketext-Simple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-Module-CoreList");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-Module-Loaded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-Object-Accessor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-Package-Constants");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-Pod-Escapes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-Time-Piece");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-tests");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Scientific Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/RedHat/release');
if (isnull(release) || 'Scientific Linux' >!< release) audit(AUDIT_OS_NOT, 'Scientific Linux');
os_ver = pregmatch(pattern: "Scientific Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Scientific Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Scientific Linux 7.x', 'Scientific Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Scientific Linux', cpu);

pkgs = [
    {'reference':'perl-5.16.3-299.el7_9', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'perl-core-5.16.3-299.el7_9', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'perl-CPAN-1.9800-299.el7_9', 'release':'SL7'},
    {'reference':'perl-debuginfo-5.16.3-299.el7_9', 'cpu':'i686', 'release':'SL7'},
    {'reference':'perl-debuginfo-5.16.3-299.el7_9', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'perl-devel-5.16.3-299.el7_9', 'cpu':'i686', 'release':'SL7'},
    {'reference':'perl-devel-5.16.3-299.el7_9', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'perl-ExtUtils-CBuilder-0.28.2.6-299.el7_9', 'release':'SL7'},
    {'reference':'perl-ExtUtils-Embed-1.30-299.el7_9', 'release':'SL7'},
    {'reference':'perl-ExtUtils-Install-1.58-299.el7_9', 'release':'SL7'},
    {'reference':'perl-IO-Zlib-1.10-299.el7_9', 'release':'SL7'},
    {'reference':'perl-libs-5.16.3-299.el7_9', 'cpu':'i686', 'release':'SL7'},
    {'reference':'perl-libs-5.16.3-299.el7_9', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'perl-Locale-Maketext-Simple-0.21-299.el7_9', 'release':'SL7'},
    {'reference':'perl-macros-5.16.3-299.el7_9', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'perl-Module-CoreList-2.76.02-299.el7_9', 'release':'SL7'},
    {'reference':'perl-Module-Loaded-0.08-299.el7_9', 'release':'SL7'},
    {'reference':'perl-Object-Accessor-0.42-299.el7_9', 'release':'SL7'},
    {'reference':'perl-Package-Constants-0.02-299.el7_9', 'release':'SL7'},
    {'reference':'perl-Pod-Escapes-1.04-299.el7_9', 'release':'SL7'},
    {'reference':'perl-tests-5.16.3-299.el7_9', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'perl-Time-Piece-1.20.1-299.el7_9', 'cpu':'x86_64', 'release':'SL7'}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  sp = NULL;
  cpu = NULL;
  el_string = NULL;
  rpm_spec_vers_cmp = NULL;
  epoch = NULL;
  allowmaj = NULL;
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'perl / perl-CPAN / perl-ExtUtils-CBuilder / etc');
}
