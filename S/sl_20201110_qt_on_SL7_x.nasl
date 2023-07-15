##
# (C) Tenable Network Security, Inc.
##
# The descriptive text is (C) Scientific Linux.
#

include('compat.inc');

if (description)
{
  script_id(142820);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/24");

  script_cve_id("CVE-2020-17507");
  script_xref(name:"RHSA", value:"RHSA-2020:5021");

  script_name(english:"Scientific Linux Security Update : qt on SL7.x i686/x86_64 (2020:5021)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote Scientific Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Scientific Linux 7 host has packages installed that are affected by a vulnerability as referenced in the
SLSA-2020:5021-1 advisory.

  - qt: buffer over-read in read_xbm_body in gui/image/qxbmhandler.cpp (CVE-2020-17507)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.scientificlinux.org/category/sl-errata/slsa-20205021-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-17507");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fermilab:scientific_linux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt-assistant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt-demos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt-devel-private");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt-qdbusviewer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt-qvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtbase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtbase-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtbase-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtbase-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtbase-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtbase-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtbase-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtbase-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtbase-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtbase-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtbase-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-rpm-macros");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Scientific Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'qt-4.8.7-9.el7_9', 'cpu':'i686', 'release':'SL7'},
    {'reference':'qt-4.8.7-9.el7_9', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'qt-assistant-4.8.7-9.el7_9', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'qt-config-4.8.7-9.el7_9', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'qt-debuginfo-4.8.7-9.el7_9', 'cpu':'i686', 'release':'SL7'},
    {'reference':'qt-debuginfo-4.8.7-9.el7_9', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'qt-demos-4.8.7-9.el7_9', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'qt-devel-4.8.7-9.el7_9', 'cpu':'i686', 'release':'SL7'},
    {'reference':'qt-devel-4.8.7-9.el7_9', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'qt-devel-private-4.8.7-9.el7_9', 'release':'SL7'},
    {'reference':'qt-doc-4.8.7-9.el7_9', 'release':'SL7'},
    {'reference':'qt-examples-4.8.7-9.el7_9', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'qt-mysql-4.8.7-9.el7_9', 'cpu':'i686', 'release':'SL7'},
    {'reference':'qt-mysql-4.8.7-9.el7_9', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'qt-odbc-4.8.7-9.el7_9', 'cpu':'i686', 'release':'SL7'},
    {'reference':'qt-odbc-4.8.7-9.el7_9', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'qt-postgresql-4.8.7-9.el7_9', 'cpu':'i686', 'release':'SL7'},
    {'reference':'qt-postgresql-4.8.7-9.el7_9', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'qt-qdbusviewer-4.8.7-9.el7_9', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'qt-qvfb-4.8.7-9.el7_9', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'qt-x11-4.8.7-9.el7_9', 'cpu':'i686', 'release':'SL7'},
    {'reference':'qt-x11-4.8.7-9.el7_9', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'qt5-qtbase-5.9.7-5.el7_9', 'cpu':'i686', 'release':'SL7'},
    {'reference':'qt5-qtbase-5.9.7-5.el7_9', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'qt5-qtbase-common-5.9.7-5.el7_9', 'release':'SL7'},
    {'reference':'qt5-qtbase-debuginfo-5.9.7-5.el7_9', 'cpu':'i686', 'release':'SL7'},
    {'reference':'qt5-qtbase-debuginfo-5.9.7-5.el7_9', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'qt5-qtbase-devel-5.9.7-5.el7_9', 'cpu':'i686', 'release':'SL7'},
    {'reference':'qt5-qtbase-devel-5.9.7-5.el7_9', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'qt5-qtbase-doc-5.9.7-5.el7_9', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'qt5-qtbase-examples-5.9.7-5.el7_9', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'qt5-qtbase-gui-5.9.7-5.el7_9', 'cpu':'i686', 'release':'SL7'},
    {'reference':'qt5-qtbase-gui-5.9.7-5.el7_9', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'qt5-qtbase-mysql-5.9.7-5.el7_9', 'cpu':'i686', 'release':'SL7'},
    {'reference':'qt5-qtbase-mysql-5.9.7-5.el7_9', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'qt5-qtbase-odbc-5.9.7-5.el7_9', 'cpu':'i686', 'release':'SL7'},
    {'reference':'qt5-qtbase-odbc-5.9.7-5.el7_9', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'qt5-qtbase-postgresql-5.9.7-5.el7_9', 'cpu':'i686', 'release':'SL7'},
    {'reference':'qt5-qtbase-postgresql-5.9.7-5.el7_9', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'qt5-qtbase-static-5.9.7-5.el7_9', 'cpu':'i686', 'release':'SL7'},
    {'reference':'qt5-qtbase-static-5.9.7-5.el7_9', 'cpu':'x86_64', 'release':'SL7'},
    {'reference':'qt5-rpm-macros-5.9.7-5.el7_9', 'release':'SL7'}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'qt / qt-assistant / qt-config / etc');
}
