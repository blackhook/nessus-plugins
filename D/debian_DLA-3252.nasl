#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3252. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(169445);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/16");

  script_cve_id(
    "CVE-2020-8813",
    "CVE-2020-23226",
    "CVE-2020-25706",
    "CVE-2022-0730",
    "CVE-2022-46169"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/03/09");

  script_name(english:"Debian DLA-3252-1 : cacti - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has a package installed that is affected by multiple vulnerabilities as referenced in the
dla-3252 advisory.

  - Multiple Cross Site Scripting (XSS) vulneratiblities exist in Cacti 1.2.12 in (1) reports_admin.php, (2)
    data_queries.php, (3) data_input.php, (4) graph_templates.php, (5) graphs.php, (6) reports_admin.php, and
    (7) data_input.php. (CVE-2020-23226)

  - A cross-site scripting (XSS) vulnerability exists in templates_import.php (Cacti 1.2.13) due to Improper
    escaping of error message during template import preview in the xml_path field (CVE-2020-25706)

  - graph_realtime.php in Cacti 1.2.8 allows remote attackers to execute arbitrary OS commands via shell
    metacharacters in a cookie, if a guest user has the graph real-time privilege. (CVE-2020-8813)

  - Under certain ldap conditions, Cacti authentication can be bypassed with certain credential types.
    (CVE-2022-0730)

  - Cacti is an open source platform which provides a robust and extensible operational monitoring and fault
    management framework for users. In affected versions a command injection vulnerability allows an
    unauthenticated user to execute arbitrary code on a server running Cacti, if a specific data source was
    selected for any monitored device. The vulnerability resides in the `remote_agent.php` file. This file can
    be accessed without authentication. This function retrieves the IP address of the client via
    `get_client_addr` and resolves this IP address to the corresponding hostname via `gethostbyaddr`. After
    this, it is verified that an entry within the `poller` table exists, where the hostname corresponds to the
    resolved hostname. If such an entry was found, the function returns `true` and the client is authorized.
    This authorization can be bypassed due to the implementation of the `get_client_addr` function. The
    function is defined in the file `lib/functions.php` and checks serval `$_SERVER` variables to determine
    the IP address of the client. The variables beginning with `HTTP_` can be arbitrarily set by an attacker.
    Since there is a default entry in the `poller` table with the hostname of the server running Cacti, an
    attacker can bypass the authentication e.g. by providing the header `Forwarded-For: <TARGETIP>`. This way
    the function `get_client_addr` returns the IP address of the server running Cacti. The following call to
    `gethostbyaddr` will resolve this IP address to the hostname of the server, which will pass the `poller`
    hostname check because of the default entry. After the authorization of the `remote_agent.php` file is
    bypassed, an attacker can trigger different actions. One of these actions is called `polldata`. The called
    function `poll_for_data` retrieves a few request parameters and loads the corresponding `poller_item`
    entries from the database. If the `action` of a `poller_item` equals `POLLER_ACTION_SCRIPT_PHP`, the
    function `proc_open` is used to execute a PHP script. The attacker-controlled parameter `$poller_id` is
    retrieved via the function `get_nfilter_request_var`, which allows arbitrary strings. This variable is
    later inserted into the string passed to `proc_open`, which leads to a command injection vulnerability. By
    e.g. providing the `poller_id=;id` the `id` command is executed. In order to reach the vulnerable call,
    the attacker must provide a `host_id` and `local_data_id`, where the `action` of the corresponding
    `poller_item` is set to `POLLER_ACTION_SCRIPT_PHP`. Both of these ids (`host_id` and `local_data_id`) can
    easily be bruteforced. The only requirement is that a `poller_item` with an `POLLER_ACTION_SCRIPT_PHP`
    action exists. This is very likely on a productive instance because this action is added by some
    predefined templates like `Device - Uptime` or `Device - Polling Time`. This command injection
    vulnerability allows an unauthenticated user to execute arbitrary commands if a `poller_item` with the
    `action` type `POLLER_ACTION_SCRIPT_PHP` (`2`) is configured. The authorization bypass should be prevented
    by not allowing an attacker to make `get_client_addr` (file `lib/functions.php`) return an arbitrary IP
    address. This could be done by not honoring the `HTTP_...` `$_SERVER` variables. If these should be kept
    for compatibility reasons it should at least be prevented to fake the IP address of the server running
    Cacti. This vulnerability has been addressed in both the 1.2.x and 1.3.x release branches with `1.2.23`
    being the first release containing the patch. (CVE-2022-46169)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=951832");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/cacti");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-3252");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-23226");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-25706");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-8813");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0730");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-46169");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/cacti");
  script_set_attribute(attribute:"solution", value:
"Upgrade the cacti packages.

For Debian 10 buster, these problems have been fixed in version 1.2.2+ds1-2+deb10u5.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8813");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-46169");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Cacti 1.2.22 unauthenticated command injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cacti");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'cacti', 'reference': '1.2.2+ds1-2+deb10u5'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var _release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (_release && prefix && reference) {
    if (deb_check(release:_release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cacti');
}
