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
  script_id(134256);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/20");
  script_xref(name:"FreeBSD", value:"SA-20:09.ntp");

  script_name(english:"FreeBSD : ntp -- Multiple vulnerabilities (591a706b-5cdc-11ea-9a0a-206a8a720317)");
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
"nwtime.org reports :

Three ntp vulnerabilities, Depending on configuration, may have little
impact up to termination of the ntpd process.

NTP Bug 3610: Process_control() should exit earlier on short packets.
On systems that override the default and enable ntpdc (mode 7) fuzz
testing detected that a short packet will cause ntpd to read
uninitialized data.

NTP Bug 3596: An unauthenticated unmonitored ntpd is vulnerable to
attack on IPv4 with highly predictable transmit timestamps. An
off-path attacker who can query time from the victim's ntp which
receives time from an unauthenticated time source must be able to send
from a spoofed IPv4 address of upstream ntp server and and the victim
must be able to process a large number of packets with the spoofed
IPv4 address of the upstream server. After eight or more successful
attacks in a row the attacker can either modify the victim's clock by
a small amount or cause ntpd to terminate. The attack is especially
effective when unusually short poll intervals have been configured.

NTP Bug 3592: The fix for https://bugs.ntp.org/3445 introduced a bug
such that a ntp can be prevented from initiating a time volley to its
peer resulting in a DoS.

All three NTP bugs may result in DoS or terimation of the ntp daemon."
  );
  # https://vuxml.freebsd.org/freebsd/591a706b-5cdc-11ea-9a0a-206a8a720317.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?300313a1"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ntp-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/06");
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

if (pkg_test(save_report:TRUE, pkg:"ntp<4.2.8p14")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ntp-devel<=4.3.99_6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
