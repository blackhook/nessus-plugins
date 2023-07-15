#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2020-5862.
#

include('compat.inc');

if (description)
{
  script_id(140926);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2017-7529", "CVE-2018-16845", "CVE-2019-9511");
  script_bugtraq_id(99534, 105868);
  script_xref(name:"CEA-ID", value:"CEA-2019-0643");

  script_name(english:"Oracle Linux 7 : olcne / nginx (ELSA-2020-5862)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2020-5862 advisory.

  - Nginx versions since 0.5.6 up to and including 1.13.2 are vulnerable to integer overflow vulnerability in
    nginx range filter module resulting into leak of potentially sensitive information triggered by specially
    crafted request. (CVE-2017-7529)

  - nginx before versions 1.15.6, 1.14.1 has a vulnerability in the ngx_http_mp4_module, which might allow an
    attacker to cause infinite loop in a worker process, cause a worker process crash, or might result in
    worker process memory disclosure by using a specially crafted mp4 file. The issue only affects nginx if it
    is built with the ngx_http_mp4_module (the module is not built by default) and the .mp4. directive is used
    in the configuration file. Further, the attack is only possible if an attacker is able to trigger
    processing of a specially crafted mp4 file with the ngx_http_mp4_module. (CVE-2018-16845)

  - Some HTTP/2 implementations are vulnerable to window size manipulation and stream prioritization
    manipulation, potentially leading to a denial of service. The attacker requests a large amount of data
    from a specified resource over multiple streams. They manipulate window size and stream priority to force
    the server to queue the data in 1-byte chunks. Depending on how efficiently this data is queued, this can
    consume excess CPU, memory, or both. (CVE-2019-9511)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://linux.oracle.com/errata/ELSA-2020-5862.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16845");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2017-7529");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nginx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nginx-all-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nginx-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nginx-mod-http-image-filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nginx-mod-http-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nginx-mod-http-xslt-filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nginx-mod-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nginx-mod-stream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:olcne-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:olcne-api-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:olcne-nginx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:olcne-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:olcnectl");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 7', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);
if ('x86_64' >!< cpu) audit(AUDIT_ARCH_NOT, 'x86_64', cpu);

pkgs = [
    {'reference':'nginx-1.17.7-2.el7', 'cpu':'x86_64', 'release':'7', 'epoch':'1'},
    {'reference':'nginx-all-modules-1.17.7-2.el7', 'release':'7', 'epoch':'1'},
    {'reference':'nginx-filesystem-1.17.7-2.el7', 'release':'7', 'epoch':'1'},
    {'reference':'nginx-mod-http-image-filter-1.17.7-2.el7', 'cpu':'x86_64', 'release':'7', 'epoch':'1'},
    {'reference':'nginx-mod-http-perl-1.17.7-2.el7', 'cpu':'x86_64', 'release':'7', 'epoch':'1'},
    {'reference':'nginx-mod-http-xslt-filter-1.17.7-2.el7', 'cpu':'x86_64', 'release':'7', 'epoch':'1'},
    {'reference':'nginx-mod-mail-1.17.7-2.el7', 'cpu':'x86_64', 'release':'7', 'epoch':'1'},
    {'reference':'nginx-mod-stream-1.17.7-2.el7', 'cpu':'x86_64', 'release':'7', 'epoch':'1'},
    {'reference':'olcne-agent-1.0.8-2.el7', 'cpu':'x86_64', 'release':'7'},
    {'reference':'olcne-api-server-1.0.8-2.el7', 'cpu':'x86_64', 'release':'7'},
    {'reference':'olcne-nginx-1.0.8-2.el7', 'cpu':'x86_64', 'release':'7'},
    {'reference':'olcne-utils-1.0.8-2.el7', 'cpu':'x86_64', 'release':'7'},
    {'reference':'olcnectl-1.0.8-2.el7', 'cpu':'x86_64', 'release':'7'}
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
  rpm_prefix = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['rpm_prefix'])) rpm_prefix = package_array['rpm_prefix'];
  if (reference && release) {
    if (rpm_prefix) {
        if (rpm_exists(release:release, rpm:rpm_prefix) && rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'nginx / nginx-all-modules / nginx-filesystem / etc');
}