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
  script_id(92906);
  script_version("2.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2014-3952", "CVE-2014-3953");
  script_bugtraq_id(68466, 68467);
  script_xref(name:"FreeBSD", value:"SA-14:17.kmem");

  script_name(english:"FreeBSD : FreeBSD -- Kernel memory disclosure in control messages and SCTP (7240de58-6007-11e6-a6c3-14dae9d210b8)");
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
"Buffer between control message header and data may not be completely
initialized before being copied to userland. [CVE-2014-3952]

Three SCTP cmsgs, SCTP_SNDRCV, SCTP_EXTRCV and SCTP_RCVINFO, have
implicit padding that may not be completely initialized before being
copied to userland. In addition, three SCTP notifications,
SCTP_PEER_ADDR_CHANGE, SCTP_REMOTE_ERROR and
SCTP_AUTHENTICATION_EVENT, have padding in the returning data
structure that may not be completely initialized before being copied
to userland. [CVE-2014-3953] Impact : An unprivileged local process
may be able to retrieve portion of kernel memory.

For the generic control message, the process may be able to retrieve a
maximum of 4 bytes of kernel memory.

For SCTP, the process may be able to retrieve 2 bytes of kernel memory
for all three control messages, plus 92 bytes for SCTP_SNDRCV and 76
bytes for SCTP_EXTRCV. If the local process is permitted to receive
SCTP notification, a maximum of 112 bytes of kernel memory may be
returned to userland.

This information might be directly useful, or it might be leveraged to
obtain elevated privileges in some way. For example, a terminal buffer
might include a user-entered password."
  );
  # https://vuxml.freebsd.org/freebsd/7240de58-6007-11e6-a6c3-14dae9d210b8.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?52d6c079"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:FreeBSD");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"FreeBSD Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/FreeBSD/release", "Host/FreeBSD/pkg_info", "Settings/ParanoidReport");

  exit(0);
}


include("audit.inc");
include("freebsd_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/FreeBSD/release")) audit(AUDIT_OS_NOT, "FreeBSD");
if (!get_kb_item("Host/FreeBSD/pkg_info")) audit(AUDIT_PACKAGE_LIST_MISSING);


if (report_paranoia < 2) audit(AUDIT_PARANOID);

flag = 0;

if (pkg_test(save_report:TRUE, pkg:"FreeBSD>=10.0<10.0_7")) flag++;
if (pkg_test(save_report:TRUE, pkg:"FreeBSD>=9.2<9.2_10")) flag++;
if (pkg_test(save_report:TRUE, pkg:"FreeBSD>=9.1<9.1_17")) flag++;
if (pkg_test(save_report:TRUE, pkg:"FreeBSD>=8.4<8.4_14")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
