#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2018-844a1e9778.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(107032);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2018-1000002");
  script_xref(name:"FEDORA", value:"2018-844a1e9778");

  script_name(english:"Fedora 26 : knot-resolver (2018-844a1e9778)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Knot Resolver 2.1.0 (2018-02-16) ================================

Incompatible changes

--------------------

  - stats: remove tracking of expiring records (predict uses
    another way)

  - systemd: re-use a single kresd.socket and
    kresd-tls.socket

  - ta_sentinel: implement protocol
    draft-ietf-dnsop-kskroll-sentinel-01 (our
    draft-ietf-dnsop-kskroll-sentinel-00 implementation had
    inverted logic)

  - libknot: require version 2.6.4 or newer to get bugfixes
    for DNS-over-TLS

Bugfixes

--------

  - detect_time_jump module: don't clear cache on
    suspend-resume (#284)

  - stats module: fix stats.list() returning nothing,
    regressed in 2.0.0

  - policy.TLS_FORWARD: refusal when configuring with
    multiple IPs (#306)

  - cache: fix broken refresh of insecure records that were
    about to expire

  - fix the hints module on some systems, e.g. Fedora (came
    back on 2.0.0)

  - build with older gnutls (conditionally disable features)

  - fix the predict module to work with insecure records &
    cleanup code

Knot Resolver 2.0.0 (2018-01-31) ================================

Incompatible changes

--------------------

  - systemd: change unit files to allow running multiple
    instances, deployments with single instance now must use
    `kresd@1.service` instead of `kresd.service`; see
    kresd.systemd(7) for details

  - systemd: the directory for cache is now
    /var/cache/knot-resolver

  - unify default directory and user to `knot-resolver`

  - directory with trust anchor file specified by -k option
    must be writeable

  - policy module is now loaded by default to enforce RFC
    6761; see documentation for policy.PASS if you use
    locally-served DNS zones

  - drop support for alternative cache backends memcached,
    redis, and for Lua bindings for some specific cache
    operations

  - REORDER_RR option is not implemented (temporarily)

New features

------------

  - aggressive caching of validated records (RFC 8198) for
    NSEC zones; thanks to ICANN for sponsoring this work.

  - forwarding over TLS, authenticated by SPKI pin or
    certificate. policy.TLS_FORWARD pipelines queries
    out-of-order over shared TLS connection Beware: Some
    resolvers do not support out-of-order query processing.
    TLS forwarding to such resolvers will lead to slower
    resolution or failures.

  - trust anchors: you may specify a read-only file via -K
    or --keyfile-ro

  - trust anchors: at build-time you may set KEYFILE_DEFAULT
    (read-only)

  - ta_sentinel module implements draft
    ietf-dnsop-kskroll-sentinel-00, enabled by default

  - serve_stale module is prototype, subject to change

  - extended API for Lua modules

Bugfixes

--------

  - fix build on osx - regressed in 1.5.3 (different linker
    option name)

----

Knot Resolver 1.5.3 (2018-01-23) ================================

Bugfixes

--------

  - fix the hints module on some systems, e.g. Fedora.
    Symptom: `undefined symbol: engine_hint_root_file`

Knot Resolver 1.5.2 (2018-01-22) ================================

Security

--------

  - fix CVE-2018-1000002: insufficient DNSSEC validation,
    allowing attackers to deny existence of some data by
    forging packets. Some combinations pointed out in RFC
    6840 sections 4.1 and 4.3 were not taken into account.

Bugfixes

--------

  - memcached: fix fallout from module rename in 1.5.1

Knot Resolver 1.5.1 (2017-12-12) ================================

Incompatible changes

--------------------

  - script supervisor.py was removed, please migrate to a
    real process manager

  - module ketcd was renamed to etcd for consistency

  - module kmemcached was renamed to memcached for
    consistency

Bugfixes

--------

  - fix SIGPIPE crashes (#271)

  - tests: work around out-of-space for platforms with
    larger memory pages

  - lua: fix mistakes in bindings affecting 1.4.0 and 1.5.0
    (and 1.99.1-alpha), potentially causing problems in
    dns64 and workarounds modules

  - predict module: various fixes (!399)

Improvements

------------

  - add priming module to implement RFC 8109, enabled by
    default (#220)

  - add modules helping with system time problems, enabled
    by default; for details see documentation of
    detect_time_skew and detect_time_jump

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2018-844a1e9778"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected knot-resolver package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:knot-resolver");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:26");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/28");
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
if (rpm_check(release:"FC26", reference:"knot-resolver-2.1.0-1.fc26")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "knot-resolver");
}
