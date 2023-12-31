#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2018 Jacques Vidrine and contributors
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

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(65542);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2013-1640", "CVE-2013-1652", "CVE-2013-1653", "CVE-2013-1654", "CVE-2013-1655", "CVE-2013-2275");

  script_name(english:"FreeBSD : puppet27 and puppet -- multiple vulnerabilities (cda566a0-2df0-4eb0-b70e-ed7a6fb0ab3c)");
  script_summary(english:"Checks for updated packages in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote FreeBSD host is missing one or more security-related
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Moses Mendoza reports :

A vulnerability found in Puppet could allow an authenticated client to
cause the master to execute arbitrary code while responding to a
catalog request. Specifically, in order to exploit the vulnerability,
the puppet master must be made to invoke the 'template' or
'inline_template' functions during catalog compilation.

A vulnerability found in Puppet could allow an authenticated client to
connect to a puppet master and perform unauthorized actions.
Specifically, given a valid certificate and private key, an agent
could retrieve catalogs from the master that it is not authorized to
access or it could poison the puppet master's caches for any
puppet-generated data that supports caching such as catalogs, nodes,
facts, and resources. The extent and severity of this vulnerability
varies depending on the specific configuration of the master: for
example, whether it is using storeconfigs or not, which version,
whether it has access to the cache or not, etc.

A vulnerability has been found in Puppet which could allow
authenticated clients to execute arbitrary code on agents that have
been configured to accept kick connections. This vulnerability is not
present in the default configuration of puppet agents, but if they
have been configured to listen for incoming connections
('listen=true'), and the agent's auth.conf has been configured to
allow access to the `run` REST endpoint, then a client could construct
an HTTP request which could execute arbitrary code. The severity of
this issue is exacerbated by the fact that puppet agents typically run
as root.

A vulnerability has been found in Puppet that could allow a client
negotiating a connection to a master to downgrade the master's SSL
protocol to SSLv2. This protocol has been found to contain design
weaknesses. This issue only affects systems running older versions
(pre 1.0.0) of openSSL. Newer versions explicitly disable SSLv2.

A vulnerability found in Puppet could allow unauthenticated clients to
send requests to the puppet master which would cause it to load code
unsafely. While there are no reported exploits, this vulnerability
could cause issues like those described in Rails CVE-2013-0156. This
vulnerability only affects puppet masters running Ruby 1.9.3 and
higher.

This vulnerability affects puppet masters 0.25.0 and above. By
default, auth.conf allows any authenticated node to submit a report
for any other node. This can cause issues with compliance. The
defaults in auth.conf have been changed."
  );
  # https://puppetlabs.com/security/cve/cve-2013-1640/
  script_set_attribute(
    attribute:"see_also",
    value:"https://puppet.com/security/cve/cve-2013-1640"
  );
  # https://puppetlabs.com/security/cve/cve-2013-1652/
  script_set_attribute(
    attribute:"see_also",
    value:"https://puppet.com/security/cve/cve-2013-1652"
  );
  # https://puppetlabs.com/security/cve/cve-2013-1653/
  script_set_attribute(
    attribute:"see_also",
    value:"https://puppet.com/security/cve/cve-2013-1653"
  );
  # https://puppetlabs.com/security/cve/cve-2013-1654/
  script_set_attribute(
    attribute:"see_also",
    value:"https://puppet.com/security/cve/cve-2013-1654"
  );
  # https://puppetlabs.com/security/cve/cve-2013-1655/
  script_set_attribute(
    attribute:"see_also",
    value:"https://puppet.com/security/cve/cve-2013-1655"
  );
  # https://puppetlabs.com/security/cve/cve-2013-2275/
  script_set_attribute(
    attribute:"see_also",
    value:"https://puppet.com/security/cve/cve-2013-2275"
  );
  # https://groups.google.com/forum/?fromgroups=#!topic/puppet-announce/f_gybceSV6E
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?36c89c29"
  );
  # https://groups.google.com/forum/?fromgroups=#!topic/puppet-announce/kgDyaPhHniw
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5569885b"
  );
  # https://vuxml.freebsd.org/freebsd/cda566a0-2df0-4eb0-b70e-ed7a6fb0ab3c.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?300a3186"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:puppet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:puppet27");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"FreeBSD Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/FreeBSD/release", "Host/FreeBSD/pkg_info");

  exit(0);
}


include("audit.inc");
include("freebsd_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/FreeBSD/release")) audit(AUDIT_OS_NOT, "FreeBSD");
if (!get_kb_item("Host/FreeBSD/pkg_info")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;

if (pkg_test(save_report:TRUE, pkg:"puppet>=3.0<3.1.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"puppet27>=2.7<2.7.21")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
