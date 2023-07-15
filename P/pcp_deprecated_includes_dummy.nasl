#
# (C) Tenable Network Security, Inc.
#

# prevents the engine from attempting to compile this plugin
#pragma nocompile(product:nessus, compile_mode:dynamic)

if (description)
{
  script_id(137405);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/23");

  script_name(english:"Agent deployment helper plugin");

  script_set_attribute(attribute:"synopsis",value:"
  Agent deployment helper plugin");
  script_set_attribute(attribute:"description",value:"
  This plugin is for use to help with
  deployment of optimized libraries on agents.");
  script_set_attribute(attribute:"solution", value:"n/a" );
  script_set_attribute(attribute:"risk_factor", value:"None" );

  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/15");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_attribute(attribute:"plugin_type", value:"settings");
  script_end_attributes();

  script_category(ACT_SETTINGS);
  script_family(english:"Settings");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  exit(0);
}

function script_cvs_date()
{
  local_var v;
  v = split(_FCT_ANON_ARGS[0], sep: ' ', keep: 0);
  if ( isnull(v) || isnull(v[1]) || v[1] !~ "^2[0-9]+/[0-9]+/[0-9]+$" ) return;
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/23");
}

#pragma static(include)
include("audit_nlib.inc");
include("data_protection_nlib.inc");
include("global_settings_nlib.inc");
include("http_cookie_jar.inc");
include("http_login.inc");
include("http_misc_func.inc");
namespace pcp
{
  include("http_network5.inc");
}
include("http_network.inc");
include("http_request.inc");
include("lcx_globals.inc");
include("misc_func_nlib.inc");
include("mssql_ssrp.inc");
include("obj_nlib.inc");
include("smb2_func.inc");
include("smb_cifs.inc");
include("smb_dcerpc.inc");
include("smb_file.inc");
include("smb_glue.inc");
include("smb_header.inc");
include("smb_internals.inc");
include("smb_lsa.inc");
include("smb_net.inc");
include("smb_reg.inc");
include("smb_sam.inc");
include("smb_svc.inc");
include("ssh_get_info2_aix.inc");
include("ssh_get_info2_amazonlinux.inc");
include("ssh_get_info2_arista_eos.inc");
include("ssh_get_info2_centos.inc");
include("ssh_get_info2_checkpoint_gaia.inc");
include("ssh_get_info2_cisco_aci.inc");
include("ssh_get_info2_cisco_asa_cx.inc");
include("ssh_get_info2_cisco_asa.inc");
include("ssh_get_info2_cisco_firepower.inc");
include("ssh_get_info2_cisco_fmc.inc");
include("ssh_get_info2_cisco.inc");
include("ssh_get_info2_cisco_ios.inc");
include("ssh_get_info2_cisco_ios_xr.inc");
include("ssh_get_info2_cisco_ise.inc");
include("ssh_get_info2_cisco_ucos.inc");
include("ssh_get_info2_container_linux.inc");
include("ssh_get_info2_debian.inc");
include("ssh_get_info2_euleros.inc");
include("ssh_get_info2_exos.inc");
include("ssh_get_info2_f5_bigip_bash.inc");
include("ssh_get_info2_f5_bigip.inc");
include("ssh_get_info2_fedora.inc");
include("ssh_get_info2_freebsd.inc");
include("ssh_get_info2_gentoo.inc");
include("ssh_get_info2_hpux.inc");
include("ssh_get_info2_linux.inc");
include("ssh_get_info2_mac.inc");
include("ssh_get_info2_mcafee.inc");
include("ssh_get_info2_montavista.inc");
include("ssh_get_info2_netapp.inc");
include("ssh_get_info2_netbsd.inc");
include("ssh_get_info2_nix.inc");
include("ssh_get_info2_nxos.inc");
include("ssh_get_info2_openbsd.inc");
include("ssh_get_info2_oracle_linux.inc");
include("ssh_get_info2_oracle_vm.inc");
include("ssh_get_info2_photon_os.inc");
include("ssh_get_info2_rancher_os.inc");
include("ssh_get_info2_rhel.inc");
include("ssh_get_info2_rios.inc");
include("ssh_get_info2_scientific_linux.inc");
include("ssh_get_info2_slackware.inc");
include("ssh_get_info2_solaris.inc");
include("ssh_get_info2_suse.inc");
include("ssh_get_info2_symantec_cas.inc");
include("ssh_get_info2_timos.inc");
include("ssh_get_info2_virtuozzo_linux.inc");
include("ssh_get_info2_windows.inc");
include("ssh_get_info2_windriverlinux.inc");
include("ssh_get_info2_zscaleros.inc");
include("ssh_get_info2_zte_cgsl.inc");
include("ssh_lib_basic_shell_handler.inc");
include("ssh_lib_channel.inc");
include("ssh_lib_checkpoint_shell_manager.inc");
include("ssh_lib_cipherset.inc");
include("ssh_lib_cisco_adeos_shell_handler.inc");
include("ssh_lib_cisco_ucos_shell_handler.inc");
include("ssh_lib_client_cb.inc");
include("ssh_lib_cmd_logger.inc");
include("ssh_lib_exos_shell_handler.inc");
include("ssh_lib_firepower_shell_handlers.inc");
include("ssh_lib_firepower_shell_manager.inc");
include("ssh_lib_ios_shell_handler.inc");
include("ssh_lib_kex.inc");
include("ssh_lib_netapp_shell_handler.inc");
include("ssh_lib_sftp.inc");
include("ssh_lib_shell_handler.inc");
include("ssh_lib_shell_handler_misc.inc");
include("ssh_lib_shell_manager_base.inc");
include("ssh_lib_shell_manager_basic_escl.inc");
include("ssh_lib_state.inc");
include("ssh_lib_timos_shell_handler.inc");
include("ssh_lib_tmsh_shell_handler.inc");
include("ssh_lib_util.inc");
include("string_pack.inc");
include("string_printf.inc");
include("torture_cgi_delay.inc");
include("torture_cgi_err_msg.inc");
include("torture_cgi_func.inc");
include("torture_cgi_headers.inc");
include("torture_cgi_load_estimation.inc");
include("torture_cgi_names.inc");
include("torture_cgi_param_names.inc");
include("torture_cgi_pers_XSS_RE.inc");
include("torture_cgi_sql_inj_msg.inc");
include("torture_cgi_xpath_msg.inc");
include("torture_cgi_yesno.inc");
#pragma static(include:false)
exit(0, "This plugin doesn't do anything intentionally.");
