#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2020 Jacques Vidrine and contributors
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

include("compat.inc");

if (description)
{
  script_id(144182);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/16");

  script_cve_id("CVE-2020-11036");

  script_name(english:"FreeBSD : glpi -- multiple related stored XSS vulnerabilities (27a230a2-3b11-11eb-af2a-080027dbe4b7)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"MITRE Corporation reports :

In GLPI before version 9.4.6 there are multiple related stored XSS
vulnerabilities. The package is vulnerable to Stored XSS in the
comments of items in the Knowledge base. Adding a comment with content
'alert(1)' reproduces the attack. This can be exploited by a user with
administrator privileges in the User-Agent field. It can also be
exploited by an outside party through the following steps: 1. Create a
user with the surname `' onmouseover='alert(document.cookie)` and an
empty first name. 2. With this user, create a ticket 3. As an
administrator (or other privileged user) open the created ticket 4. On
the 'last update' field, put your mouse on the name of the user 5. The
XSS fires This is fixed in version 9.4.6."
  );
  # https://github.com/glpi-project/glpi/security/advisories/GHSA-3g3h-rwhr-7385
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f763be83"
  );
  # https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/5WQMONZRWLWOXMHMYWR7A5Q5JJERPMVC/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b66a378c"
  );
  # https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/Q4BG2UTINBVV7MTJRXKBQ26GV2UINA6L/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c0228f6b"
  );
  # https://vuxml.freebsd.org/freebsd/27a230a2-3b11-11eb-af2a-080027dbe4b7.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d388499e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:glpi");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/14");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (pkg_test(save_report:TRUE, pkg:"glpi<9.4.6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:pkg_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
