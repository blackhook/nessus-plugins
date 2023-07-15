#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2023-c9b2182a4e
#

include('compat.inc');

if (description)
{
  script_id(171802);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/22");

  script_cve_id(
    "CVE-2022-1996",
    "CVE-2022-23524",
    "CVE-2022-23526",
    "CVE-2022-41717"
  );
  script_xref(name:"FEDORA", value:"2023-c9b2182a4e");

  script_name(english:"Fedora 37 : golang-github-need-being-tree / golang-helm-3 / golang-oras / golang-oras-1 / golang-oras-2 (2023-c9b2182a4e)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 37 host has packages installed that are affected by multiple vulnerabilities as referenced in the
FEDORA-2023-c9b2182a4e advisory.

  - Authorization Bypass Through User-Controlled Key in GitHub repository emicklei/go-restful prior to v3.8.0.
    (CVE-2022-1996)

  - Helm is a tool for managing Charts, pre-configured Kubernetes resources. Versions prior to 3.10.3 are
    subject to Uncontrolled Resource Consumption, resulting in Denial of Service. Input to functions in the
    _strvals_ package can cause a stack overflow. In Go, a stack overflow cannot be recovered from.
    Applications that use functions from the _strvals_ package in the Helm SDK can have a Denial of Service
    attack when they use this package and it panics. This issue has been patched in 3.10.3. SDK users can
    validate strings supplied by users won't create large arrays causing significant memory usage before
    passing them to the _strvals_ functions. (CVE-2022-23524)

  - Helm is a tool for managing Charts, pre-configured Kubernetes resources. Versions prior to 3.10.3 are
    subject to NULL Pointer Dereference in the_chartutil_ package that can cause a segmentation violation. The
    _chartutil_ package contains a parser that loads a JSON Schema validation file. For example, the Helm
    client when rendering a chart will validate its values with the schema file. The _chartutil_ package
    parses the schema file and loads it into structures Go can work with. Some schema files can cause array
    data structures to be created causing a memory violation. Applications that use the _chartutil_ package in
    the Helm SDK to parse a schema file can suffer a Denial of Service when that input causes a panic that
    cannot be recovered from. Helm is not a long running service so the panic will not affect future uses of
    the Helm client. This issue has been patched in 3.10.3. SDK users can validate schema files that are
    correctly formatted before passing them to the _chartutil_ functions. (CVE-2022-23526)

  - An attacker can cause excessive memory growth in a Go server accepting HTTP/2 requests. HTTP/2 server
    connections contain a cache of HTTP header keys sent by the client. While the total number of entries in
    this cache is capped, an attacker sending very large keys can cause the server to allocate approximately
    64 MiB per open connection. (CVE-2022-41717)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-c9b2182a4e");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-1996");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:37");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:golang-github-need-being-tree");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:golang-helm-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:golang-oras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:golang-oras-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:golang-oras-2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Fedora' >!< os_release) audit(AUDIT_OS_NOT, 'Fedora');
var os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Fedora');
os_ver = os_ver[1];
if (! preg(pattern:"^37([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 37', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'golang-github-need-being-tree-0.1.0-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-helm-3-3.11.1-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-oras-0.15.1-1.20221105git690716b.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-oras-1-1.2.1-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-oras-2-2.0.0~rc.4-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && _release) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'golang-github-need-being-tree / golang-helm-3 / golang-oras / etc');
}
