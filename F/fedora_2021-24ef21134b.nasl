##
# (C) Tenable Network Security, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2021-24ef21134b
#

include('compat.inc');

if (description)
{
  script_id(144965);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/12");

  script_cve_id(
    "CVE-2018-17825",
    "CVE-2019-14690",
    "CVE-2019-14691",
    "CVE-2019-14692",
    "CVE-2019-14732",
    "CVE-2019-14733",
    "CVE-2019-14734",
    "CVE-2019-15151"
  );
  script_xref(name:"FEDORA", value:"2021-24ef21134b");

  script_name(english:"Fedora 32 : adplug / audacious-plugins / ocp (2021-24ef21134b)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 32 host has packages installed that are affected by multiple vulnerabilities as referenced in the
FEDORA-2021-24ef21134b advisory.

  - An issue was discovered in AdPlug 2.3.1. There are several double-free vulnerabilities in the CEmuopl
    class in emuopl.cpp because of a destructor's two OPLDestroy calls, each of which frees TL_TABLE,
    SIN_TABLE, AMS_TABLE, and VIB_TABLE. (CVE-2018-17825)

  - AdPlug 2.3.1 has a heap-based buffer overflow in CxadbmfPlayer::__bmf_convert_stream() in bmf.cpp.
    (CVE-2019-14690)

  - AdPlug 2.3.1 has a heap-based buffer overflow in CdtmLoader::load() in dtm.cpp. (CVE-2019-14691)

  - AdPlug 2.3.1 has a heap-based buffer overflow in CmkjPlayer::load() in mkj.cpp. (CVE-2019-14692)

  - AdPlug 2.3.1 has multiple heap-based buffer overflows in Ca2mLoader::load() in a2m.cpp. (CVE-2019-14732)

  - AdPlug 2.3.1 has multiple heap-based buffer overflows in CradLoader::load() in rad.cpp. (CVE-2019-14733)

  - AdPlug 2.3.1 has multiple heap-based buffer overflows in CmtkLoader::load() in mtk.cpp. (CVE-2019-14734)

  - AdPlug 2.3.1 has a double free in the Cu6mPlayer class in u6m.h. (CVE-2019-15151)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2021-24ef21134b");
  script_set_attribute(attribute:"solution", value:
"Update the affected adplug, audacious-plugins and / or ocp packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-15151");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:adplug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:audacious-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ocp");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/RedHat/release');
if (isnull(release) || 'Fedora' >!< release) audit(AUDIT_OS_NOT, 'Fedora');
os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Fedora');
os_ver = os_ver[1];
if (! preg(pattern:"^32([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 32', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

pkgs = [
    {'reference':'adplug-2.3.3-1.fc32', 'release':'FC32', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'audacious-plugins-3.10.1-7.fc32', 'release':'FC32', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocp-0.1.22-0.28.git849cc42.fc32', 'release':'FC32', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'adplug / audacious-plugins / ocp');
}
