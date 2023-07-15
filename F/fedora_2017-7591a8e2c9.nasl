#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2017-7591a8e2c9.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101214);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_xref(name:"FEDORA", value:"2017-7591a8e2c9");

  script_name(english:"Fedora 25 : globus-ftp-client / globus-gass-cache-program / globus-gass-copy / etc (2017-7591a8e2c9)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"globus-ftp-client

  - Adapt to Perl 5.26 - POSIX::tmpnam() no longer available

  - Remove some redundant tests to reduce test time

globus-gass-cache-program

  - GT6 update

globus-gass-copy

  - Don't attempt sshftp data protection without creds
    (9.24)

  - Checksum verification based on contribution from IBM
    (9.24)

  - Fix uninitialized field related crash (9.25)

  - Remove checksum data from public handle (9.26)

  - Prevent some race conditions (9.27)

globus-gram-job-manager

  - Default to running personal gatekeeper on an ephemeral
    port

globus-gridftp-server

  - New error message format (12.0)

  - Configuration database (12.0)

  - Better delay for end of session ref check (12.1)

  - Fix tests when getgroups() does not return effective gid
    (12.2)

globus-gssapi-gsi

  - Don't unlock unlocked mutex (12.14)

  - Remove legacy SSLv3 support (12.15)

  - Test fixes (12.16)

  - Drop patch globus-gssapi-gsi-mutex-unlock.patch (fixed
    upstream 12.14)

globus-io

  - Remove legacy SSLv3 support

globus-net-manager

  - Fix .pc typo

  - Drop patch globus-net-manager-pkgconfig.patch (fixed
    upstream)

globus-xio

  - Don't rely on globus_error_put(NULL) to be
    GLOBUS_SUCCESS (5.15)

  - Fix crash in error handling in http driver (5.16)

globus-xio-gsi-driver

  - Fix crash when checking for anonymous GSS name when name
    comparison fails

globus-xio-pipe-driver

  - Fix .pc typo

globus-xio-udt-driver

  - Don't force --static flag to pkg-config

  - Drop some BuildRequires no longer needed with above
    change

  - Fix undefined symbols during linking

myproxy

  - Fix error check (6.1.26)

  - Remove legacy SSLv3 support (6.1.27)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2017-7591a8e2c9"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:globus-ftp-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:globus-gass-cache-program");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:globus-gass-copy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:globus-gram-job-manager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:globus-gridftp-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:globus-gssapi-gsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:globus-io");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:globus-net-manager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:globus-xio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:globus-xio-gsi-driver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:globus-xio-pipe-driver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:globus-xio-udt-driver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:myproxy");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:25");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/05");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^25([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 25", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC25", reference:"globus-ftp-client-8.35-2.fc25")) flag++;
if (rpm_check(release:"FC25", reference:"globus-gass-cache-program-6.7-1.fc25")) flag++;
if (rpm_check(release:"FC25", reference:"globus-gass-copy-9.27-1.fc25")) flag++;
if (rpm_check(release:"FC25", reference:"globus-gram-job-manager-14.36-1.fc25")) flag++;
if (rpm_check(release:"FC25", reference:"globus-gridftp-server-12.2-1.fc25")) flag++;
if (rpm_check(release:"FC25", reference:"globus-gssapi-gsi-12.16-1.fc25")) flag++;
if (rpm_check(release:"FC25", reference:"globus-io-11.9-1.fc25")) flag++;
if (rpm_check(release:"FC25", reference:"globus-net-manager-0.17-1.fc25")) flag++;
if (rpm_check(release:"FC25", reference:"globus-xio-5.16-1.fc25")) flag++;
if (rpm_check(release:"FC25", reference:"globus-xio-gsi-driver-3.11-1.fc25")) flag++;
if (rpm_check(release:"FC25", reference:"globus-xio-pipe-driver-3.10-1.fc25")) flag++;
if (rpm_check(release:"FC25", reference:"globus-xio-udt-driver-1.27-1.fc25")) flag++;
if (rpm_check(release:"FC25", reference:"myproxy-6.1.28-1.fc25")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "globus-ftp-client / globus-gass-cache-program / globus-gass-copy / etc");
}
