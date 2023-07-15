#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2018-812b5d5a71.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(110327);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2018-6085", "CVE-2018-6086", "CVE-2018-6087", "CVE-2018-6088", "CVE-2018-6089", "CVE-2018-6090", "CVE-2018-6091", "CVE-2018-6092", "CVE-2018-6093", "CVE-2018-6094", "CVE-2018-6095", "CVE-2018-6096", "CVE-2018-6097", "CVE-2018-6098", "CVE-2018-6099", "CVE-2018-6100", "CVE-2018-6101", "CVE-2018-6102", "CVE-2018-6103", "CVE-2018-6104", "CVE-2018-6105", "CVE-2018-6106", "CVE-2018-6107", "CVE-2018-6108", "CVE-2018-6109", "CVE-2018-6110", "CVE-2018-6111", "CVE-2018-6112", "CVE-2018-6113", "CVE-2018-6114", "CVE-2018-6115", "CVE-2018-6116", "CVE-2018-6117", "CVE-2018-6118", "CVE-2018-6120", "CVE-2018-6121", "CVE-2018-6122");
  script_xref(name:"FEDORA", value:"2018-812b5d5a71");

  script_name(english:"Fedora 27 : chromium (2018-812b5d5a71)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to 66.0.3359.181. Security fix for CVE-2018-6085 CVE-2018-6086
CVE-2018-6087 CVE-2018-6088 CVE-2018-6089 CVE-2018-6090 CVE-2018-6091
CVE-2018-6092 CVE-2018-6093 CVE-2018-6094 CVE-2018-6095 CVE-2018-6096
CVE-2018-6097 CVE-2018-6098 CVE-2018-6099 CVE-2018-6100 CVE-2018-6101
CVE-2018-6102 CVE-2018-6103 CVE-2018-6104 CVE-2018-6105 CVE-2018-6106
CVE-2018-6107 CVE-2018-6108 CVE-2018-6109 CVE-2018-6110 CVE-2018-6111
CVE-2018-6112 CVE-2018-6113 CVE-2018-6114 CVE-2018-6116 CVE-2018-6117
CVE-2018-6118 CVE-2018-6121 CVE-2018-6122 CVE-2018-6120

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2018-812b5d5a71"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected chromium package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:27");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^27([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 27", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC27", reference:"chromium-66.0.3359.181-2.fc27")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "chromium");
}
