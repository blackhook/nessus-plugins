#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2018-39be36e9fc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(120356);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2018-16065", "CVE-2018-16066", "CVE-2018-16067", "CVE-2018-16068", "CVE-2018-16069", "CVE-2018-16070", "CVE-2018-16071", "CVE-2018-16072", "CVE-2018-16073", "CVE-2018-16074", "CVE-2018-16075", "CVE-2018-16076", "CVE-2018-16077", "CVE-2018-16078", "CVE-2018-16079", "CVE-2018-16080", "CVE-2018-16081", "CVE-2018-16082", "CVE-2018-16083", "CVE-2018-16084", "CVE-2018-16085", "CVE-2018-16086", "CVE-2018-16087", "CVE-2018-16088", "CVE-2018-16428", "CVE-2018-16429", "CVE-2018-17458", "CVE-2018-17459", "CVE-2018-6055", "CVE-2018-6119");
  script_xref(name:"FEDORA", value:"2018-39be36e9fc");

  script_name(english:"Fedora 29 : chromium (2018-39be36e9fc)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Security fixes for CVE-2018-6055 CVE-2018-6119 CVE-2018-16429
CVE-2018-16428

----

Update to Chromium 69. (EPEL-7 update is blocked by a GCC bug:
1629813, so as soon as devtoolset-8 arrives...)

Fixes a lot of security issues, like every major release of Chromium,
including CVE-2018-16087 CVE-2018-16088 CVE-2018-16086CVE-2018-16065
CVE-2018-16066 CVE-2018-16067 CVE-2018-16068 CVE-2018-16069
CVE-2018-16070 CVE-2018-16071 CVE-2018-16072 CVE-2018-16073
CVE-2018-16074 CVE-2018-16075 CVE-2018-16076 CVE-2018-16077
CVE-2018-16078

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2018-39be36e9fc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected chromium package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:29");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Fedora Local Security Checks");

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
if (! preg(pattern:"^29([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 29", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC29", reference:"chromium-69.0.3497.100-1.fc29")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "chromium");
}
