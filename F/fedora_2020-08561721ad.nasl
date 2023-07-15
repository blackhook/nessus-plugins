#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2020-08561721ad.
#

include("compat.inc");

if (description)
{
  script_id(138069);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/26");

  script_cve_id("CVE-2020-6463", "CVE-2020-6465", "CVE-2020-6466", "CVE-2020-6467", "CVE-2020-6468", "CVE-2020-6469", "CVE-2020-6470", "CVE-2020-6471", "CVE-2020-6472", "CVE-2020-6473", "CVE-2020-6474", "CVE-2020-6475", "CVE-2020-6476", "CVE-2020-6477", "CVE-2020-6478", "CVE-2020-6479", "CVE-2020-6480", "CVE-2020-6481", "CVE-2020-6482", "CVE-2020-6483", "CVE-2020-6484", "CVE-2020-6485", "CVE-2020-6486", "CVE-2020-6487", "CVE-2020-6488", "CVE-2020-6489", "CVE-2020-6490", "CVE-2020-6491", "CVE-2020-6505", "CVE-2020-6506", "CVE-2020-6507", "CVE-2020-6509");
  script_xref(name:"FEDORA", value:"2020-08561721ad");

  script_name(english:"Fedora 32 : chromium (2020-08561721ad)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Update to 83.0.4103.116. Fixes CVE-2020-6509.

----

Black Lives Matter. Saying this does not mean that other lives do not
matter. It should not be controversial to say this. If I say Chromium
updates matter, it does not mean that other Fedora packages do not
matter, it means that a Chromium update is needed to fix this giant
pile of severe security vulnerabilities, here, today, now :

CVE-2020-6463 CVE-2020-6465 CVE-2020-6466 CVE-2020-6467 CVE-2020-6468
CVE-2020-6469 CVE-2020-6470 CVE-2020-6471 CVE-2020-6472 CVE-2020-6473
CVE-2020-6474 CVE-2020-6475 CVE-2020-6476 CVE-2020-6478 CVE-2020-6479
CVE-2020-6480 CVE-2020-6481 CVE-2020-6482 CVE-2020-6483 CVE-2020-6484
CVE-2020-6485 CVE-2020-6486 CVE-2020-6487 CVE-2020-6488 CVE-2020-6489
CVE-2020-6490 CVE-2020-6491 CVE-2020-6505 CVE-2020-6506 CVE-2020-6507

In making that analogy, I do not intend to trivialize BLM. In no way
do I mean to compare the lives of people to a silly web browser
update. People are infinitely important than software. But since I'm
here to push this software update out, I am also choosing to say
clearly and unambiguously that Black Lives Matter. 

Open Source proves that many voices, many contributions, together can
change the world. It depends on it. This is my voice.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2020-08561721ad"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected chromium package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-6509");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:32");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^32([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 32", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC32", reference:"chromium-83.0.4103.116-3.fc32", allowmaj:TRUE)) flag++;


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
