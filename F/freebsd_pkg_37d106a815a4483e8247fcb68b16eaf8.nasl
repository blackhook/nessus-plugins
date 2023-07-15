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

include('compat.inc');

if (description)
{
  script_id(136706);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/13");

  script_cve_id("CVE-2020-10957", "CVE-2020-10958", "CVE-2020-10967");

  script_name(english:"FreeBSD : Dovecot -- Multiple vulnerabilities (37d106a8-15a4-483e-8247-fcb68b16eaf8)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"Aki Tuomi reports :

Vulnerability Details : Sending malformed NOOP command causes crash in
submission, submission-login or lmtp service.

Risk : Remote attacker can keep submission-login service down, causing
denial of service attack. For lmtp the risk is neglible, as lmtp is
usually behind a trusted MTA.

Steps to reproduce : Send ``NOOP EE'FY`` to submission port, or
similarly malformed command.

Vulnerability Details :

Sending command followed by sufficient number of newlines triggers a
use-after-free bug that might crash submission-login, submission or
lmtp service.

Risk :

Remote attacker can keep submission-login service down, causing denial
of service attack. For lmtp the risk is neglible, as lmtp is usually
behind a trusted MTA.

Steps to reproduce :

This can be currently reproduced with ASAN or Valgrind. Reliable way
to crash has not yet been discovered.

Vulnerability Details : Sending mail with empty quoted localpart
causes submission or lmtp component to crash.

Risk : Malicious actor can cause denial of service to mail delivery by
repeatedly sending mails with bad sender or recipient address.

Steps to reproduce : Send mail with envelope sender or recipient as
<''@example.org>.

Workaround : For submission there is no workaround, but triggering the
bug requires valid credentials. For lmtp, one can implement sufficient
filtering on MTA level to prevent mails with such addresses from
ending up in LMTP delivery.");
  script_set_attribute(attribute:"see_also", value:"https://dovecot.org/pipermail/dovecot-news/2020-May/000438.html");
  # https://vuxml.freebsd.org/freebsd/37d106a8-15a4-483e-8247-fcb68b16eaf8.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3f67388d");
  script_set_attribute(attribute:"solution", value:
"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-10967");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-10957");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:dovecot");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FreeBSD Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if (pkg_test(save_report:TRUE, pkg:"dovecot<2.3.10.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
