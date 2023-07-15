#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2020:4628.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157612);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/14");

  script_cve_id("CVE-2020-12802", "CVE-2020-12803");
  script_xref(name:"ALSA", value:"2020:4628");

  script_name(english:"AlmaLinux 8 : libreoffice (ALSA-2020:4628)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2020:4628 advisory.

  - LibreOffice has a 'stealth mode' in which only documents from locations deemed 'trusted' are allowed to
    retrieve remote resources. This mode is not the default mode, but can be enabled by users who want to
    disable LibreOffice's ability to include remote resources within a document. A flaw existed where remote
    graphic links loaded from docx documents were omitted from this protection prior to version 6.4.4. This
    issue affects: The Document Foundation LibreOffice versions prior to 6.4.4. (CVE-2020-12802)

  - ODF documents can contain forms to be filled out by the user. Similar to HTML forms, the contained form
    data can be submitted to a URI, for example, to an external web server. To create submittable forms, ODF
    implements the XForms W3C standard, which allows data to be submitted without the need for macros or other
    active scripting Prior to version 6.4.4 LibreOffice allowed forms to be submitted to any URI, including
    file: URIs, enabling form submissions to overwrite local files. User-interaction is required to submit the
    form, but to avoid the possibility of malicious documents engineered to maximize the possibility of
    inadvertent user submission this feature has now been limited to http[s] URIs, removing the possibility to
    overwrite local files. This issue affects: The Document Foundation LibreOffice versions prior to 6.4.4.
    (CVE-2020-12803)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/8/ALSA-2020-4628.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected libcmis, libreoffice-sdk and / or libreoffice-sdk-doc packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12803");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libcmis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libreoffice-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libreoffice-sdk-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AlmaLinux/release", "Host/AlmaLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/AlmaLinux/release');
if (isnull(release) || 'AlmaLinux' >!< release) audit(AUDIT_OS_NOT, 'AlmaLinux');
var os_ver = pregmatch(pattern: "AlmaLinux release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'AlmaLinux');
var os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'AlmaLinux 8.x', 'AlmaLinux ' + os_ver);

if (!get_kb_item('Host/AlmaLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

var pkgs = [
    {'reference':'libcmis-0.5.2-1.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcmis-0.5.2-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libreoffice-sdk-6.3.6.2-3.el8.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libreoffice-sdk-doc-6.3.6.2-3.el8.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'Alma-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && release && (!exists_check || rpm_exists(release:release, rpm:exists_check))) {
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libcmis / libreoffice-sdk / libreoffice-sdk-doc');
}
