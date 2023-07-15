#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2018-04b3af1edf.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(111235);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2018-6758", "CVE-2018-7490");
  script_xref(name:"FEDORA", value:"2018-04b3af1edf");

  script_name(english:"Fedora 27 : uwsgi (2018-04b3af1edf)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Conditionally disable router-access for tcp_wrappers
    deprecation (Jorge Gallegos)

  - Updated to 2.0.16 which includes fix for CVE-2018-6758
    (Jorge Gallegos)

---

  - Modernize and generalize building of Python 
subpackages :

  - replace python with python2

  - use appropriate macros for when refering to Python 3

  - prefix Python-dependent plugins with the version of
    Python they are built with

  - Also build Python 3 subpackages for the other Python 3
    version in EPEL7

---

  - Build Python 3 version(s) of gevent plugin on Fedora and
    EPEL7

  - Build Python 3 version of greenlet plugin on Fedora and
    EPEL7

  - Build Python 2 version of greenlet plugin on EPEL7

  - Always build Python 3 version of tornado plugin when
    building with Python 3 (drop python3_tornado build
    conditional)

---

  - Latest upstream (rhbz#1549354)

  - Enable uwsgi-plugin-coroae on EL7

  - Use systemd tmpfiles to create /run/uwsgi with group
    write permissions (rhbz#1427303)

  - Use /var/run/uwsgi when not using systemd

  - Build with versioned python command

  - Remove %%config from systemd unit file

  - Disable greenlet plugin on EL7

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2018-04b3af1edf"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected uwsgi package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"uWSGI Path Traversal File Disclosure");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:uwsgi");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:27");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/24");
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
if (rpm_check(release:"FC27", reference:"uwsgi-2.0.17.1-1.fc27")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "uwsgi");
}
