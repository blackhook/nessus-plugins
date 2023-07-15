#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2017-4603342f9a.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(105707);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2017-16927");
  script_xref(name:"FEDORA", value:"2017-4603342f9a");

  script_name(english:"Fedora 26 : 1:xrdp (2017-4603342f9a)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Security fixes

  - Fix local denial of service CVE-2017-16927 #958 #979
    (fix already in 0.9.4-2)

New features

  - Add a new log level TRACE more verbose than DEBUG #835
    #944

  - SSH agent forwarding via RDP #867 #868
    FreeRDP/FreeRDP#4122

  - Support horizontal wheel properly #928

Bug fixes

  - Avoid use of hard-coded sesman port #895

  - Workaround for corrupted display with Windows Server
    2008 using NeutrinoRDP #869

  - Fix glitch in audio redirection by AAC #910 #936

  - Implement vsock support #930 #935 #948

  - Avoid 100% CPU usage on SSL accept #956

Other changes

  - Add US Dvorak keyboard #929

  - Suppress some misleading logs #964

  - Add Finnish keyboard #972

  - Add more user-friendlier description about Xorg config
    #974

  - Renew pulseaudio document #984 #985

  - Lots of cleanups and refactoring

Known issues

  - Audio redirection by MP3 codec doesn't sound with some
    client, use AAC instead #965

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2017-4603342f9a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected 1:xrdp package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:1:xrdp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:26");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/10");
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
if (! preg(pattern:"^26([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 26", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC26", reference:"xrdp-0.9.5-1.fc26", epoch:"1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "1:xrdp");
}
