#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2018-906ba26b4d.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(120615);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2017-6926",
    "CVE-2017-6927",
    "CVE-2017-6930",
    "CVE-2017-6931",
    "CVE-2018-7600"
  );
  script_xref(name:"FEDORA", value:"2018-906ba26b4d");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2019-0240");

  script_name(english:"Fedora 28 : drupal8 (2018-906ba26b4d) (Drupalgeddon 2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"-
    [8.4.6](https://www.drupal.org/project/drupal/releases/8
    .4.6)

  - [SA-CORE-2018-002
    (CVE-2018-7600)](https://www.drupal.org/SA-CORE-2018-002
    )

  -
    [8.4.5](https://www.drupal.org/project/drupal/releases/8
    .4.5)

  - [SA-CORE-2018-001 (CVE-2017-6926 / CVE-2017-6927 /
    CVE-2017-6930 /
    CVE-2017-6931)](https://www.drupal.org/SA-CORE-2018-001)

  -
    [8.4.4](https://www.drupal.org/project/drupal/releases/8
    .4.4)

  -
    [8.4.3](https://www.drupal.org/project/drupal/releases/8
    .4.3)

  -
    [8.4.2](https://www.drupal.org/project/drupal/releases/8
    .4.2)

  -
    [8.4.1](https://www.drupal.org/project/drupal/releases/8
    .4.1)

  -
    [8.4.0](https://www.drupal.org/project/drupal/releases/8
    .4.0)

  -
    [8.4.0-rc2](https://www.drupal.org/project/drupal/releas
    es/8.4.0-rc2)

  -
    [8.4.0-rc1](https://www.drupal.org/project/drupal/releas
    es/8.4.0-rc1)

  -
    [8.4.0-beta1](https://www.drupal.org/project/drupal/rele
    ases/8.4.0-beta1)

  -
    [8.4.0-alpha1](https://www.drupal.org/project/drupal/rel
    eases/8.4.0-alpha1)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2018-906ba26b4d");
  script_set_attribute(attribute:"solution", value:
"Update the affected drupal8 package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Drupal 8 SA-CORE-2018-002 RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Drupal Drupalgeddon 2 Forms API Property Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:drupal8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:28");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! preg(pattern:"^28([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 28", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC28", reference:"drupal8-8.4.6-3.fc28")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "drupal8");
}
