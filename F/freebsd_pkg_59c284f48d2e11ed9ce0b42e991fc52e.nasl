#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2021 Jacques Vidrine and contributors
#
# Redistribution and use in source (VuXML) and 'compiled' forms (SGML,
# HTML, PDF, PostScript, RTF and so forth) with or without modification,
# are permitted provided that the following conditions are met:
# 1. Redistributions of source code (VuXML) must retain the above
#    copyright notice, this list of conditions and the following
#    disclaimer as the first lines of this file unmodified.
# 2. Redistributions in compiled form (transformed to other DTDs,
#    published online in any format, converted to PDF, PostScript,
#    RTF and other formats) must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer
#    in the documentation and/or other materials provided with the
#    distribution.
#
# THIS DOCUMENTATION IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
# OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
# OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
# OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS DOCUMENTATION,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

include('compat.inc');

if (description)
{
  script_id(169701);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/16");

  script_cve_id("CVE-2022-46169");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/03/09");

  script_name(english:"FreeBSD : net-mgmt/cacti is vulnerable to remote command injection (59c284f4-8d2e-11ed-9ce0-b42e991fc52e)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the 59c284f4-8d2e-11ed-9ce0-b42e991fc52e advisory.

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

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://nvd.nist.gov/vuln/detail/CVE-2022-46169");
  # https://vuxml.freebsd.org/freebsd/59c284f4-8d2e-11ed-9ce0-b42e991fc52e.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b1464ea2");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-46169");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Cacti 1.2.22 unauthenticated command injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:cacti");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FreeBSD Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/FreeBSD/release", "Host/FreeBSD/pkg_info");

  exit(0);
}


include("freebsd_package.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/FreeBSD/release")) audit(AUDIT_OS_NOT, "FreeBSD");
if (!get_kb_item("Host/FreeBSD/pkg_info")) audit(AUDIT_PACKAGE_LIST_MISSING);


var flag = 0;

var packages = [
    'cacti<1.2.23'
];

foreach var package( packages ) {
    if (pkg_test(save_report:TRUE, pkg: package)) flag++;
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : pkg_report_get()
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
