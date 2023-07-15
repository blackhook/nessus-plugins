#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2018-fd194a1f14.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(120933);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/08");

  script_cve_id(
    "CVE-2018-16435",
    "CVE-2018-17462",
    "CVE-2018-17463",
    "CVE-2018-17464",
    "CVE-2018-17465",
    "CVE-2018-17466",
    "CVE-2018-17467",
    "CVE-2018-17468",
    "CVE-2018-17469",
    "CVE-2018-17470",
    "CVE-2018-17471",
    "CVE-2018-17472",
    "CVE-2018-17473",
    "CVE-2018-17474",
    "CVE-2018-17475",
    "CVE-2018-17476",
    "CVE-2018-17477",
    "CVE-2018-17478",
    "CVE-2018-17479",
    "CVE-2018-5179"
  );
  script_xref(name:"FEDORA", value:"2018-fd194a1f14");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/22");

  script_name(english:"Fedora 28 : chromium (2018-fd194a1f14)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"Security fix for CVE-2018-17478 CVE-2018-17479. Update to
70.0.3538.110.

----

Update to chromium 70.0.3538.77. Fixes CVE-2018-16435 CVE-2018-17462
CVE-2018-17463 CVE-2018-17464 CVE-2018-17465 CVE-2018-17466
CVE-2018-17467 CVE-2018-17468 CVE-2018-17469 CVE-2018-17470
CVE-2018-17471 CVE-2018-17473 CVE-2018-17474 CVE-2018-17475
CVE-2018-17476 CVE-2018-5179 CVE-2018-17477

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2018-fd194a1f14");
  script_set_attribute(attribute:"solution", value:
"Update the affected chromium package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-17479");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Google Chrome 67, 68 and 69 Object.create exploit');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:chromium");
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
if (rpm_check(release:"FC28", reference:"chromium-70.0.3538.110-1.fc28")) flag++;


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
