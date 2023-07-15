#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2020-39e0b8bd14.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(134990);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2019-20446", "CVE-2019-20503", "CVE-2020-10531", "CVE-2020-6378", "CVE-2020-6379", "CVE-2020-6380", "CVE-2020-6381", "CVE-2020-6382", "CVE-2020-6383", "CVE-2020-6384", "CVE-2020-6385", "CVE-2020-6386", "CVE-2020-6387", "CVE-2020-6388", "CVE-2020-6389", "CVE-2020-6390", "CVE-2020-6391", "CVE-2020-6392", "CVE-2020-6393", "CVE-2020-6394", "CVE-2020-6395", "CVE-2020-6396", "CVE-2020-6397", "CVE-2020-6398", "CVE-2020-6399", "CVE-2020-6400", "CVE-2020-6401", "CVE-2020-6402", "CVE-2020-6403", "CVE-2020-6404", "CVE-2020-6405", "CVE-2020-6406", "CVE-2020-6407", "CVE-2020-6408", "CVE-2020-6409", "CVE-2020-6410", "CVE-2020-6411", "CVE-2020-6412", "CVE-2020-6413", "CVE-2020-6414", "CVE-2020-6415", "CVE-2020-6416", "CVE-2020-6417", "CVE-2020-6418", "CVE-2020-6420", "CVE-2020-6422", "CVE-2020-6424", "CVE-2020-6425", "CVE-2020-6426", "CVE-2020-6427", "CVE-2020-6428", "CVE-2020-6429", "CVE-2020-6449");
  script_xref(name:"FEDORA", value:"2020-39e0b8bd14");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2020-0023");

  script_name(english:"Fedora 30 : chromium (2020-39e0b8bd14)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Update to 80.0.3987.149. Upstream says it fixes '13' security issues,
but only lists these CVEs :

  - CVE-2020-6422: Use after free in WebGL

  - CVE-2020-6424: Use after free in media

  - CVE-2020-6425: Insufficient policy enforcement in
    extensions. 

  - CVE-2020-6426: Inappropriate implementation in V8

  - CVE-2020-6427: Use after free in audio

  - CVE-2020-6428: Use after free in audio

  - CVE-2020-6429: Use after free in audio.

  - CVE-2019-20503: Out of bounds read in usersctplib.

  - CVE-2020-6449: Use after free in audio

----

Update to 80.0.3987.132. Lots of security fixes here. VAAPI re-enabled
by default except on NVIDIA.

List of CVEs fixed (since last update) :

  - CVE-2019-20446

  - CVE-2020-6381 

  - CVE-2020-6382 

  - CVE-2020-6383 

  - CVE-2020-6384

  - CVE-2020-6385 

  - CVE-2020-6386

  - CVE-2020-6387 

  - CVE-2020-6388

  - CVE-2020-6389

  - CVE-2020-6390 

  - CVE-2020-6391

  - CVE-2020-6392 

  - CVE-2020-6393

  - CVE-2020-6394

  - CVE-2020-6395

  - CVE-2020-6396 

  - CVE-2020-6397 

  - CVE-2020-6398

  - CVE-2020-6399 

  - CVE-2020-6400 

  - CVE-2020-6401 

  - CVE-2020-6402 

  - CVE-2020-6403 

  - CVE-2020-6404 

  - CVE-2020-6405 

  - CVE-2020-6406 

  - CVE-2020-6407

  - CVE-2020-6408 

  - CVE-2020-6409 

  - CVE-2020-6410 

  - CVE-2020-6411 

  - CVE-2020-6412 

  - CVE-2020-6413 

  - CVE-2020-6414 

  - CVE-2020-6415 

  - CVE-2020-6416 

  - CVE-2020-6417

  - CVE-2020-6418

  - CVE-2020-6420 

----

Update to 79.0.3945.130. Fixes the following security issues :

  - CVE-2020-6378

  - CVE-2020-6379

  - CVE-2020-6380

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2020-39e0b8bd14"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected chromium package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-6449");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Google Chrome 80 JSCreate side-effect type confusion exploit');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:30");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^30([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 30", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC30", reference:"chromium-80.0.3987.149-1.fc30", allowmaj:TRUE)) flag++;


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
