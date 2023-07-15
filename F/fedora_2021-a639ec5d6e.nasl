##
# (C) Tenable Network Security, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2021-a639ec5d6e
#

include('compat.inc');

if (description)
{
  script_id(146855);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/12");
  script_xref(name:"FEDORA", value:"2021-a639ec5d6e");

  script_name(english:"Fedora 33 : prosody (2021-a639ec5d6e)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 33 host has a package installed that is affected by a vulnerability as referenced in the
FEDORA-2021-a639ec5d6e advisory.

  - Prosody 0.11.8 ==============  This is a new minor release for the 0.11.x stable branch, it includes bug
    fixes and performance improvements!  Upstream would like to thank the Jitsi folks for helping to improve
    websocket performance in this and the previous release.  This release also fixes a security issue, where
    channel binding, which connects the authentication layer (i.e. SASL) with the security layer (i.e. TLS) to
    detect man-in-the-middle attacks, could be used on connections encrypted with TLS 1.3, despite the holy
    texts declaring this undefined.   Security --------    * mod_saslauth: Disable tls-unique channel
    binding with TLS 1.3 (#1542)   Fixes and improvements ----------------------    * net.websocket.frames:
    Improve websocket masking performance by using the new util.strbitop   * util.strbitop: Library for
    efficient bitwise operations on strings   Minor changes -------------    * MUC: Correctly advertise
    whether the subject can be changed (#1155)   * MUC: Preserve disco node attribute (or lack thereof) in
    responses (#1595)   * MUC: Fix logic bug causing unnecessary presence to be sent (#1615)   * mod_bosh: Fix
    error if client tries to connect to component (#425)   * mod_bosh: Pick out the wait before checking it
    instead of earlier   * mod_pep: Advertise base PubSub feature (#1632)   * mod_pubsub: Fix notification
    stanza type setting (#1605)   * mod_s2s: Prevent keepalives before client has established a stream   *
    net.adns: Fix bug that sent empty DNS packets (#1619)   * net.http.server: Dont send Content-Length on
    1xx/204 responses (#1596)   * net.websocket.frames: Fix length calculation bug (#1598)   * util.dbuffer:
    Make length API in line with Lua strings   * util.dbuffer: Optimize substring operations   * util.debug:
    Fix locals being reported under wrong stack frame in some cases   * util.dependencies: Fix check for Lua
    bitwise operations library (#1594)   * util.interpolation: Fix combination of filters and fallback values
    #1623   * util.promise: Preserve tracebacks   * util.stanza: Reject ASCII control characters (#1606)   *
    timers: Ensure timers cant block other processing (#1620) (FEDORA-2021-a639ec5d6e)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2021-a639ec5d6e");
  script_set_attribute(attribute:"solution", value:
"Update the affected prosody package.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:33");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:prosody");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/RedHat/release');
if (isnull(release) || 'Fedora' >!< release) audit(AUDIT_OS_NOT, 'Fedora');
os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Fedora');
os_ver = os_ver[1];
if (! preg(pattern:"^33([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 33', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

pkgs = [
    {'reference':'prosody-0.11.8-1.fc33', 'release':'FC33', 'rpm_spec_vers_cmp':TRUE}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  sp = NULL;
  cpu = NULL;
  el_string = NULL;
  rpm_spec_vers_cmp = NULL;
  epoch = NULL;
  allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && release) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'prosody');
}
