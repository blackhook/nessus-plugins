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
  script_id(135883);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2019-12387",
    "CVE-2019-9512",
    "CVE-2019-9514",
    "CVE-2019-9515",
    "CVE-2020-10108",
    "CVE-2020-10109"
  );
  script_xref(name:"CEA-ID", value:"CEA-2019-0643");

  script_name(english:"FreeBSD : py-twisted -- multiple vulnerabilities (9fbaefb3-837e-11ea-b5b4-641c67a117d8) (Ping Flood) (Reset Flood) (Settings Flood)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related
updates.");
  script_set_attribute(attribute:"description", value:
"Twisted developers reports :

All HTTP clients in twisted.web.client now raise a ValueError when
called with a method and/or URL that contain invalid characters. This
mitigates CVE-2019-12387. Thanks to Alex Brasetvik for reporting this
vulnerability.

The HTTP/2 server implementation now enforces TCP flow control on
control frame messages and times out clients that send invalid data
without reading responses. This closes CVE-2019-9512 (Ping Flood),
CVE-2019-9514 (Reset Flood), and CVE-2019-9515 (Settings Flood).
Thanks to Jonathan Looney and Piotr Sikora.

twisted.web.http was subject to several request smuggling attacks.
Requests with multiple Content-Length headers were allowed
(CVE-2020-10108, thanks to Jake Miller from Bishop Fox and ZeddYu Lu
for reporting this) and now fail with a 400; requests with a
Content-Length header and a Transfer-Encoding header honored the first
header (CVE-2020-10109, thanks to Jake Miller from Bishop Fox for
reporting this) and now fail with a 400; requests whose
Transfer-Encoding header had a value other than 'chunked' and
'identity' (thanks to ZeddYu Lu) were allowed and now fail with a 400.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/twisted/twisted/blob/twisted-20.3.0/NEWS.rst");
  script_set_attribute(attribute:"see_also", value:"https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=245252");
  # https://vuxml.freebsd.org/freebsd/9fbaefb3-837e-11ea-b5b4-641c67a117d8.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2ad22dfd");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-10109");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py27-twisted");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py35-twisted");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py36-twisted");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py37-twisted");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py38-twisted");
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

if (pkg_test(save_report:TRUE, pkg:"py27-twisted<20.3.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py35-twisted<20.3.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py36-twisted<20.3.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py37-twisted<20.3.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py38-twisted<20.3.0")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
