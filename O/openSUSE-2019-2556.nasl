#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-2556.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(131281);
  script_version("1.2");
  script_cvs_date("Date: 2019/12/09");

  script_cve_id("CVE-2019-14241");

  script_name(english:"openSUSE Security Update : haproxy (openSUSE-2019-2556)");
  script_summary(english:"Check for the openSUSE-2019-2556 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for haproxy to version 2.0.5+git0.d905f49a fixes the
following issues :

Security issue fixed :

  - CVE-2019-14241: Fixed a cookie memory corruption
    problem. (bsc#1142529)

The update to 2.0.5 brings lots of features and bugfixes :

  - new internal native HTTP representation called HTX, was
    already in 1.9 and is now enabled by default in 2.0

  - end-to-end HTTP/2 support including trailers and
    continuation frames, as needed for gRPC ; HTTP/2 may
    also be upgraded from HTTP/1.1 using the H2 preface;

  - server connection pooling and more advanced reuse, with
    ALPN protocol negotiation (already in 1.9)

  - layer 7 retries, allowing to use 0-RTT and TCP Fast Open
    to the servers as well as on the frontend

  - much more scalable multi-threading, which is even
    enabled by default on platforms where it was
    successfully tested ; by default, as many threads are
    started as the number of CPUs haproxy is allowed to run
    on. This removes a lot of configuration burden in VMs
    and containers

  - automatic maxconn setting for the process and the
    frontends, directly based on the number of available FDs
    (easier configuration in containers and with systemd)

  - logging to stdout for use in containers and systemd
    (already in 1.9). Logs can now provide micro-second
    resolution for some events

  - peers now support SSL, declaration of multiple
    stick-tables directly in the peers section, and
    synchronization of server names, not just IDs

  - In master-worker mode, the master process now exposes
    its own CLI and can communicate with all other processes
    (including the stopping ones), even allowing to connect
    to their CLI and check their state. It is also possible
    to start some sidecar programs and monitor them from the
    master, and the master can automatically kill old
    processes that survived too many reloads

  - the incoming connections are load-balanced between all
    threads depending on their load to minimize the
    processing time and maximize the capacity (already in
    1.9)

  - the SPOE connection load-balancing was significantly
    improved in order to reduce high percentiles of SPOA
    response time (already in 1.9)

  - the 'random' load balancing algorithm and a
    power-of-two-choices variant were introduced

  - statistics improvements with per-thread counters for
    certain things, and a prometheus exporter for all our
    statistics;

  - lots of debugging help, it's easier to produce a core
    dump, there are new commands on the CLI to control
    various things, there is a watchdog to fail cleanly when
    a thread deadlock or a spinning task are detected, so
    overall it should provide a better experience in field
    and less round trips between users and developers (hence
    less stress during an incident).

  - all 3 device detection engines are now compatible with
    multi-threading and can be build-tested without any
    external dependencies

  - 'do-resolve' http-request action to perform a DNS
    resolution on any, sample, and resolvers now support
    relying on /etc/resolv.conf to match the local resolver

  - log sampling and balancing : it's now possible to send 1
    log every 10 to a server, or to spread the logging load
    over multiple log servers;

  - a new SPOA agent (spoa_server) allows to interface
    haproxy with Python and Lua programs

  - support for Solaris' event ports (equivalent of kqueue
    or epoll) which will significantly improve the
    performance there when dealing with numerous connections

  - some warnings are now reported for some deprecated
    options that will be removed in 2.1. Since 2.0 is long
    term supported, there's no emergency to convert them,
    however if you see these warnings, you need to
    understand that you're among their extremely rare users
    and just because of this you may be taking risks by
    keeping them

  - A new SOCKS4 server-side layer was provided ; it allows
    outgoing connections to be forwarded through a SOCKS4
    proxy (such as ssh -D).

  - priority- and latency- aware server queues : it is
    possible now to assign priorities to certain requests
    and/or to give them a time bonus or penalty to refine
    control of the traffic and be able to engage on SLAs.

  - internally the architecture was significantly redesigned
    to allow to further improve performance and make it
    easier to implement protocols that span over multiple
    layers (such as QUIC). This work started in 1.9 and will
    continue with 2.1.

  - the I/O, applets and tasks now share the same
    multi-threaded scheduler, giving a much better
    responsiveness and fairness between all tasks as is
    visible with the CLI which always responds instantly
    even under extreme loads (started in 1.9)

  - the internal buffers were redesigned to ease zero-copy
    operations, so that it is possible to sustain a high
    bandwidth even when forwarding HTTP/1 to/from HTTP/2
    (already in 1.9)

This update was imported from the SUSE:SLE-15-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1142529"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected haproxy packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:haproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:haproxy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:haproxy-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/25");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"haproxy-2.0.5+git0.d905f49a-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"haproxy-debuginfo-2.0.5+git0.d905f49a-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"haproxy-debugsource-2.0.5+git0.d905f49a-lp151.2.3.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "haproxy / haproxy-debuginfo / haproxy-debugsource");
}
