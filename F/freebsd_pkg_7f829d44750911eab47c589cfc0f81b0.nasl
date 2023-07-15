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
  script_id(135192);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/24");

  script_cve_id("CVE-2020-11100");

  script_name(english:"FreeBSD : HAproxy -- serious vulnerability affecting the HPACK decoder used for HTTP/2 (7f829d44-7509-11ea-b47c-589cfc0f81b0)");
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
"The HAproxy Project reports :

The main driver for this release is that it contains a fix for a
serious vulnerability that was responsibly reported last week by Felix
Wilhelm from Google Project Zero, affecting the HPACK decoder used for
HTTP/2. CVE-2020-11100 was assigned to this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mail-archive.com/haproxy@formilux.org/msg36876.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mail-archive.com/haproxy@formilux.org/msg36877.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mail-archive.com/haproxy@formilux.org/msg36878.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mail-archive.com/haproxy@formilux.org/msg36879.html"
  );
  # https://vuxml.freebsd.org/freebsd/7f829d44-7509-11ea-b47c-589cfc0f81b0.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bd694e5b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:haproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:haproxy18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:haproxy19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:haproxy21");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/03");
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

if (pkg_test(save_report:TRUE, pkg:"haproxy>=2.0.0<2.0.14")) flag++;
if (pkg_test(save_report:TRUE, pkg:"haproxy18>=1.8.0<1.8.25")) flag++;
if (pkg_test(save_report:TRUE, pkg:"haproxy19>=1.9.0<1.9.15")) flag++;
if (pkg_test(save_report:TRUE, pkg:"haproxy21>=2.1.0<2.1.4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
