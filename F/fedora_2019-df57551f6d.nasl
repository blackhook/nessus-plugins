#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2019-df57551f6d.
#

include("compat.inc");

if (description)
{
  script_id(122290);
  script_version("1.3");
  script_cvs_date("Date: 2020/02/12");

  script_cve_id("CVE-2016-7051", "CVE-2018-1000873", "CVE-2018-12022", "CVE-2018-12023", "CVE-2018-14718", "CVE-2018-14719", "CVE-2018-14720", "CVE-2018-14721", "CVE-2018-19360", "CVE-2018-19361", "CVE-2018-19362");
  script_xref(name:"FEDORA", value:"2019-df57551f6d");

  script_name(english:"Fedora 29 : bouncycastle / eclipse-jgit / eclipse-linuxtools / etc (2019-df57551f6d)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Fixes CVE-2018-14718 CVE-2018-14719 CVE-2018-19360 CVE-2018-19361
CVE-2018-19362 CVE-2018-12022 CVE-2018-12023 CVE-2018-14720
CVE-2018-14721 and CVE-2016-7051.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2019-df57551f6d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-19362");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:bouncycastle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:eclipse-jgit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:eclipse-linuxtools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:jackson-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:jackson-bom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:jackson-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:jackson-databind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:jackson-dataformat-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:jackson-dataformats-binary");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:jackson-dataformats-text");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:jackson-datatype-jdk8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:jackson-datatype-joda");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:jackson-datatypes-collections");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:jackson-jaxrs-providers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:jackson-module-jsonSchema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:jackson-modules-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:jackson-parent");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:29");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/19");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"FC29", reference:"bouncycastle-1.61-1.fc29")) flag++;
if (rpm_check(release:"FC29", reference:"eclipse-jgit-5.2.0-4.fc29")) flag++;
if (rpm_check(release:"FC29", reference:"eclipse-linuxtools-7.1.0-3.fc29")) flag++;
if (rpm_check(release:"FC29", reference:"jackson-annotations-2.9.8-1.fc29")) flag++;
if (rpm_check(release:"FC29", reference:"jackson-bom-2.9.8-1.fc29")) flag++;
if (rpm_check(release:"FC29", reference:"jackson-core-2.9.8-1.fc29")) flag++;
if (rpm_check(release:"FC29", reference:"jackson-databind-2.9.8-1.fc29")) flag++;
if (rpm_check(release:"FC29", reference:"jackson-dataformat-xml-2.9.8-1.fc29")) flag++;
if (rpm_check(release:"FC29", reference:"jackson-dataformats-binary-2.9.8-1.fc29")) flag++;
if (rpm_check(release:"FC29", reference:"jackson-dataformats-text-2.9.8-1.fc29")) flag++;
if (rpm_check(release:"FC29", reference:"jackson-datatype-jdk8-2.9.8-1.fc29")) flag++;
if (rpm_check(release:"FC29", reference:"jackson-datatype-joda-2.9.8-1.fc29")) flag++;
if (rpm_check(release:"FC29", reference:"jackson-datatypes-collections-2.9.8-1.fc29")) flag++;
if (rpm_check(release:"FC29", reference:"jackson-jaxrs-providers-2.9.8-1.fc29")) flag++;
if (rpm_check(release:"FC29", reference:"jackson-module-jsonSchema-2.9.8-1.fc29")) flag++;
if (rpm_check(release:"FC29", reference:"jackson-modules-base-2.9.8-1.fc29")) flag++;
if (rpm_check(release:"FC29", reference:"jackson-parent-2.9.1.2-1.fc29")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bouncycastle / eclipse-jgit / eclipse-linuxtools / etc");
}
