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
  script_id(102530);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-2824");

  script_name(english:"FreeBSD : Zabbix -- Remote code execution (5df8bd95-8290-11e7-93af-005056925db4)");
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
"mitre reports :

An exploitable code execution vulnerability exists in the trapper
command functionality of Zabbix Server 2.4.X. A specially crafted set
of packets can cause a command injection resulting in remote code
execution. An attacker can make requests from an active Zabbix Proxy
to trigger this vulnerability."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.zabbix.com/browse/ZBX-12349"
  );
  # https://vuxml.freebsd.org/freebsd/5df8bd95-8290-11e7-93af-005056925db4.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?795d7f75"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:zabbix2-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:zabbix2-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:zabbix22-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:zabbix22-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:zabbix3-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:zabbix3-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:zabbix32-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:zabbix32-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/17");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (pkg_test(save_report:TRUE, pkg:"zabbix2-server<=2.0.20")) flag++;
if (pkg_test(save_report:TRUE, pkg:"zabbix2-proxy<=2.0.20")) flag++;
if (pkg_test(save_report:TRUE, pkg:"zabbix22-server<2.2.19")) flag++;
if (pkg_test(save_report:TRUE, pkg:"zabbix22-proxy<2.2.19")) flag++;
if (pkg_test(save_report:TRUE, pkg:"zabbix3-server<3.0.10")) flag++;
if (pkg_test(save_report:TRUE, pkg:"zabbix3-proxy<3.0.10")) flag++;
if (pkg_test(save_report:TRUE, pkg:"zabbix32-server<3.2.7")) flag++;
if (pkg_test(save_report:TRUE, pkg:"zabbix32-proxy<3.2.7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
