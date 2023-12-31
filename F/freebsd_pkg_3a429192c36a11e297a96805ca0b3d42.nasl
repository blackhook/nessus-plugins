#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2019 Jacques Vidrine and contributors
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
  script_id(66581);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2012-4733", "CVE-2013-3368", "CVE-2013-3369", "CVE-2013-3370", "CVE-2013-3371", "CVE-2013-3372", "CVE-2013-3373", "CVE-2013-3374");

  script_name(english:"FreeBSD : RT -- multiple vulnerabilities (3a429192-c36a-11e2-97a9-6805ca0b3d42)");
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
"Thomas Sibley reports :

We discovered a number of security vulnerabilities which affect both
RT 3.8.x and RT 4.0.x. We are releasing RT versions 3.8.17 and 4.0.13
to resolve these vulnerabilities, as well as patches which apply atop
all released versions of 3.8 and 4.0.

The vulnerabilities addressed by 3.8.17, 4.0.13, and the below patches
include the following :

RT 4.0.0 and above are vulnerable to a limited privilege escalation
leading to unauthorized modification of ticket data. The DeleteTicket
right and any custom life cycle transition rights may be bypassed by
any user with ModifyTicket. This vulnerability is assigned
CVE-2012-4733.

RT 3.8.0 and above include a version of bin/rt that uses
semi-predictable names when creating tempfiles. This could possibly be
exploited by a malicious user to overwrite files with permissions of
the user running bin/rt. This vulnerability is assigned CVE-2013-3368.

RT 3.8.0 and above allow calling of arbitrary Mason components
(without control of arguments) for users who can see administration
pages. This could be used by a malicious user to run private
components which may have negative side-effects. This vulnerability is
assigned CVE-2013-3369.

RT 3.8.0 and above allow direct requests to private callback
components. Though no callback components ship with RT, this could be
used to exploit an extension or local callback which uses the
arguments passed to it insecurely. This vulnerability is assigned
CVE-2013-3370.

RT 3.8.3 and above are vulnerable to cross-site scripting (XSS) via
attachment filenames. The vector is difficult to exploit due to
parsing requirements. Additionally, RT 4.0.0 and above are vulnerable
to XSS via maliciously-crafted 'URLs' in ticket content when RT's
'MakeClicky' feature is configured. Although not believed to be
exploitable in the stock configuration, a patch is also included for
RTIR 2.6.x to add bulletproofing. These vulnerabilities are assigned
CVE-2013-3371.

RT 3.8.0 and above are vulnerable to an HTTP header injection limited
to the value of the Content-Disposition header. Injection of other
arbitrary response headers is not possible. Some (especially older)
browsers may allow multiple Content-Disposition values which could
lead to XSS. Newer browsers contain security measures to prevent this.
Thank you to Dominic Hargreaves for reporting this vulnerability. This
vulnerability is assigned CVE-2013-3372.

RT 3.8.0 and above are vulnerable to a MIME header injection in
outgoing email generated by RT. The vectors via RT's stock templates
are resolved by this patchset, but any custom email templates should
be updated to ensure that values interpolated into mail headers do not
contain newlines. This vulnerability is assigned CVE-2013-3373.

RT 3.8.0 and above are vulnerable to limited session re-use when using
the file-based session store, Apache::Session::File. RT's default
session configuration only uses Apache::Session::File for Oracle. RT
instances using Oracle may be locally configured to use the
database-backed Apache::Session::Oracle, in which case sessions are
never re-used. The extent of session re-use is limited to information
leaks of certain user preferences and caches, such as queue names
available for ticket creation. Thank you to Jenny Martin for reporting
the problem that lead to discovery of this vulnerability. This
vulnerability is assigned CVE-2013-3374."
  );
  # http://lists.bestpractical.com/pipermail/rt-announce/2013-May/000226.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e79fb8ab"
  );
  # http://lists.bestpractical.com/pipermail/rt-announce/2013-May/000227.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4c8a91ea"
  );
  # http://lists.bestpractical.com/pipermail/rt-announce/2013-May/000228.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0de2bf27"
  );
  # https://vuxml.freebsd.org/freebsd/3a429192-c36a-11e2-97a9-6805ca0b3d42.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4bc1970d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:rt38");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:rt40");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/24");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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

if (pkg_test(save_report:TRUE, pkg:"rt38>=3.8<3.8.17")) flag++;
if (pkg_test(save_report:TRUE, pkg:"rt40>=4.0<4.0.13")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
