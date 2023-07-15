#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2020-bc0050aa3d.
#

include("compat.inc");

if (description)
{
  script_id(141244);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/07");
  script_xref(name:"FEDORA", value:"2020-bc0050aa3d");

  script_name(english:"Fedora 31 : 1:libuv (2020-bc0050aa3d)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"2020.09.26, Version 1.40.0 (Stable)

Changes since version 1.39.0 :

  - udp: add UV_UDP_MMSG_FREE recv_cb flag (Ryan Liptak)

  - include: re-map UV__EPROTO from 4046 to -4046 (YuMeiJie)

  - doc: correct UV_UDP_MMSG_FREE version added (cjihrig)

  - doc: add uv_metrics_idle_time() version metadata (Ryan
    Liptak)

  - win,tty: pass through utf-16 surrogate pairs (Mustafa M)

  - unix: fix DragonFly BSD build (Aleksej Lebedev)

  - win,udp: fix error code returned by connect() (Santiago
    Gimeno)

  - src: suppress user_timeout maybe-uninitialized (Daniel
    Bevenius)

  - test: fix compiler warning (Vladim&iacute;r
    &#x10C;un&aacute;t)

  - build: fix the Haiku cmake build (David Carlier)

  - linux: fix i386 sendmmsg/recvmmsg support (Ben
    Noordhuis)

  - build: add libuv-static pkg-config file (Nikolay Mitev)

  - unix,win: add uv_timer_get_due_in() (Ulrik Strid)

  - build,unix: add QNX support (Elad Lahav)

  - include: remove incorrect UV__ERR() for EPROTO (cjihrig)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2020-bc0050aa3d"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected 1:libuv package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:1:libuv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:31");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^31([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 31", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC31", reference:"libuv-1.40.0-1.fc31", epoch:"1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "1:libuv");
}
