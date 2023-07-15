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

include("compat.inc");

if (description)
{
  script_id(107046);
  script_version("3.7");
  script_cvs_date("Date: 2019/04/05 23:25:06");

  script_cve_id("CVE-2016-1549", "CVE-2018-7170", "CVE-2018-7182", "CVE-2018-7183", "CVE-2018-7184", "CVE-2018-7185");
  script_xref(name:"FreeBSD", value:"SA-18:02.ntp");

  script_name(english:"FreeBSD : ntp -- multiple vulnerabilities (af485ef4-1c58-11e8-8477-d05099c0ae8c)");
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
"Network Time Foundation reports :

The NTP Project at Network Time Foundation is releasing ntp-4.2.8p11.

This release addresses five security issues in ntpd :

- LOW/MEDIUM: Sec 3012 / CVE-2016-1549 / VU#961909: Sybil
vulnerability: ephemeral association attack

- INFO/MEDIUM: Sec 3412 / CVE-2018-7182 / VU#961909 : ctl_getitem():
buffer read overrun leads to undefined behavior and information leak

- LOW: Sec 3415 / CVE-2018-7170 / VU#961909: Multiple authenticated
ephemeral associations

- LOW: Sec 3453 / CVE-2018-7184 / VU#961909: Interleaved symmetric
mode cannot recover from bad state

- LOW/MEDIUM: Sec 3454 / CVE-2018-7185 / VU#961909 : Unauthenticated
packet can reset authenticated interleaved association

one security issue in ntpq :

- MEDIUM: Sec 3414 / CVE-2018-7183 / VU#961909 : ntpq:decodearr() can
write beyond its buffer limit

and provides over 33 bugfixes and 32 other improvements."
  );
  # http://support.ntp.org/bin/view/Main/SecurityNotice#February_2018_ntp_4_2_8p11_NTP_S
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?706c32c8"
  );
  # https://vuxml.freebsd.org/freebsd/af485ef4-1c58-11e8-8477-d05099c0ae8c.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2ab8935d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ntp-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (pkg_test(save_report:TRUE, pkg:"ntp<4.2.8p11")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ntp-devel>0")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
