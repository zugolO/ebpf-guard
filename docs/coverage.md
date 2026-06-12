# MITRE ATT&CK Coverage Report

**Total rules:** 522  
**Techniques covered:** 149  
**Total technique mappings:** 442

## Coverage Matrix

| Technique | Name | Rule Count | Rules |
|-----------|------|-----------|-------|
| [T1003](https://attack.mitre.org/techniques/T1003) | OS Credential Dumping | 2 | sigma_memory_proc_dump, sigma_ptrace_attach |
| [T1003.007](https://attack.mitre.org/techniques/T1003/007) | — | 1 | cred_proc_maps_mass_read |
| [T1003.008](https://attack.mitre.org/techniques/T1003/008) | — | 1 | cred_shadow_read |
| [T1008](https://attack.mitre.org/techniques/T1008) | — | 1 | c2_icmp_large_payload |
| [T1011.001](https://attack.mitre.org/techniques/T1011/001) | — | 1 | exfil_raw_socket_by_non_root |
| [T1014](https://attack.mitre.org/techniques/T1014) | Rootkit | 20 | rootkit_kmod_suspicious_name, rootkit_delete_module_syscall, rootkit_proc_sysctl_write, rootkit_proc_modules_read, rootkit_kallsyms_read (+15 more) |
| [T1016](https://attack.mitre.org/techniques/T1016) | — | 1 | recon_network_config |
| [T1020](https://attack.mitre.org/techniques/T1020) | — | 1 | exfil_archive_to_network_pipe |
| [T1021](https://attack.mitre.org/techniques/T1021) | Remote Services | 2 | cloud_ext_aws_ssm_shell, cloud_ext_azure_runcommand |
| [T1021.001](https://attack.mitre.org/techniques/T1021/001) | Remote Desktop Protocol | 2 | lateral_rdp_connection, netintr_rdp_outbound |
| [T1021.002](https://attack.mitre.org/techniques/T1021/002) | SMB/Windows Admin Shares | 1 | netintr_outbound_smb |
| [T1021.004](https://attack.mitre.org/techniques/T1021/004) | SSH | 4 | lateral_ssh_from_container, lateral_ssh_keygen_new_key, mitre_ssh_agent_forward_abuse, net_long_ssh_session |
| [T1021.005](https://attack.mitre.org/techniques/T1021/005) | VNC | 1 | netintr_vnc_outbound |
| [T1021.006](https://attack.mitre.org/techniques/T1021/006) | Windows Remote Management | 2 | lateral_netcat_socat_pivot, mitre_winrm_port_connection |
| [T1027](https://attack.mitre.org/techniques/T1027) | Obfuscated Files or Information | 7 | evasion_base64_shell_decode, mitre_obfusc_base64_payload_large, mitre_obfusc_hex_encoded_exec, mitre_obfusc_gzip_payload, mitre_obfusc_char_concatenation (+2 more) |
| [T1030](https://attack.mitre.org/techniques/T1030) | — | 1 | exfil_repeated_outbound_to_same_ip |
| [T1036](https://attack.mitre.org/techniques/T1036) | Masquerading | 3 | sigma_masquerade_kernel_thread, sigma_binary_in_tmp_executed, webshell_image_extension_script |
| [T1036.003](https://attack.mitre.org/techniques/T1036/003) | — | 1 | evasion_system_binary_replace |
| [T1036.004](https://attack.mitre.org/techniques/T1036/004) | — | 1 | integrity_ld_so_preload_write |
| [T1036.005](https://attack.mitre.org/techniques/T1036/005) | Match Legitimate Name or Location | 3 | evasion_hidden_elf_in_tmp, mitre_masq_legitimate_name_in_tmp, sigma_masquerade_sshd |
| [T1036.007](https://attack.mitre.org/techniques/T1036/007) | Double File Extension | 1 | mitre_masq_double_extension |
| [T1037.002](https://attack.mitre.org/techniques/T1037/002) | — | 1 | persist_etc_profile_write |
| [T1037.004](https://attack.mitre.org/techniques/T1037/004) | — | 1 | persistence_motd_write |
| [T1040](https://attack.mitre.org/techniques/T1040) | Network Sniffing | 1 | lolbin_tcpdump_write |
| [T1041](https://attack.mitre.org/techniques/T1041) | — | 1 | exfil_large_http_post |
| [T1046](https://attack.mitre.org/techniques/T1046) | Network Service Discovery | 4 | net_portscan_indicator, netintr_syn_scan_pattern, netintr_nmap_fingerprint_ports, recon_port_scan_outbound |
| [T1048](https://attack.mitre.org/techniques/T1048) | Exfiltration Over Alternative Protocol | 3 | lolbin_curl_data_exfil, lolbin_wget_post_exfil, netintr_large_upload_port |
| [T1048.001](https://attack.mitre.org/techniques/T1048/001) | Exfiltration Over Symmetric Encrypted Non-C2 Protocol | 11 | exfil_dns_high_query_rate, exfil_dns_dga_high_score, lolbin_dns_exfil_via_dig, netintr_dns_over_nonstandard_port, netintr_dns_high_entropy_query (+6 more) |
| [T1048.002](https://attack.mitre.org/techniques/T1048/002) | Exfiltration Over Asymmetric Encrypted Non-C2 Protocol | 2 | exfil_large_tls_upload, netintr_smtp_exfil |
| [T1048.003](https://attack.mitre.org/techniques/T1048/003) | Exfiltration Over Unencrypted Non-C2 Protocol | 2 | exfil_ftp_active_connection, netintr_ftp_data_exfil |
| [T1049](https://attack.mitre.org/techniques/T1049) | — | 1 | recon_active_connections |
| [T1052](https://attack.mitre.org/techniques/T1052) | — | 1 | exfil_usb_mount |
| [T1053.001](https://attack.mitre.org/techniques/T1053/001) | At | 1 | mitre_at_job_scheduled |
| [T1053.002](https://attack.mitre.org/techniques/T1053/002) | — | 1 | persistence_at_spool_write |
| [T1053.003](https://attack.mitre.org/techniques/T1053/003) | Cron | 4 | persistence_cron_write, sigma_cron_job_created, sigma_crontab_modification, webshell_crontab_modification |
| [T1053.006](https://attack.mitre.org/techniques/T1053/006) | Systemd Timers | 2 | mitre_systemd_transient_timer, persist_systemd_path_unit |
| [T1055](https://attack.mitre.org/techniques/T1055) | Process Injection | 7 | mitre_so_injection_via_proc, privesc_sys_ptrace_gained, sigma_ptrace_attach, sigma_memfd_create_anonymous, sigma_mprotect_exec_heap (+2 more) |
| [T1057](https://attack.mitre.org/techniques/T1057) | — | 1 | recon_process_enum |
| [T1059](https://attack.mitre.org/techniques/T1059) | Command and Scripting Interpreter | 7 | lolbin_lua_exec, lolbin_perl_socket_shell, lolbin_ruby_socket_shell, sigma_perl_shell_execution, sigma_ruby_shell_execution (+2 more) |
| [T1059.004](https://attack.mitre.org/techniques/T1059/004) | Unix Shell | 13 | appexploit_cmd_injection_nc, lolbin_bash_dev_tcp, lolbin_bash_dev_udp, netintr_reverse_shell_port_4444, netintr_reverse_shell_port_1234 (+8 more) |
| [T1059.005](https://attack.mitre.org/techniques/T1059/005) | Visual Basic | 1 | lolbin_php_exec_oneliner |
| [T1059.006](https://attack.mitre.org/techniques/T1059/006) | Python | 2 | lolbin_python_socket_shell, sigma_python_exec_shell |
| [T1059.007](https://attack.mitre.org/techniques/T1059/007) | JavaScript | 3 | appexploit_nodejs_child_process, lolbin_node_exec, webshell_java_runtime_exec |
| [T1069](https://attack.mitre.org/techniques/T1069) | — | 1 | recon_sudo_privs |
| [T1070](https://attack.mitre.org/techniques/T1070) | Indicator Removal | 2 | fim_audit_rules_modified, sigma_utmp_wtmp_modified |
| [T1070.002](https://attack.mitre.org/techniques/T1070/002) | Clear Linux or Mac System Logs | 3 | evasion_log_clear, fim_syslog_modified, sigma_log_deletion |
| [T1070.003](https://attack.mitre.org/techniques/T1070/003) | Clear Command History | 1 | sigma_history_file_cleared |
| [T1070.004](https://attack.mitre.org/techniques/T1070/004) | — | 1 | evasion_self_delete |
| [T1070.006](https://attack.mitre.org/techniques/T1070/006) | — | 1 | evasion_timestamp_modify |
| [T1071](https://attack.mitre.org/techniques/T1071) | Application Layer Protocol | 3 | netintr_cobalt_strike_default_port, netintr_covenant_default_port, netintr_brute_ratel_port |
| [T1071.001](https://attack.mitre.org/techniques/T1071/001) | Web Protocols | 5 | c2_reverse_shell_standard_ports, mitre_http_c2_beacon_pattern, net_long_c2_connection, net_long_plaintext_http, net_long_https_connection |
| [T1071.004](https://attack.mitre.org/techniques/T1071/004) | DNS | 1 | mitre_dns_c2_high_frequency |
| [T1078](https://attack.mitre.org/techniques/T1078) | Valid Accounts | 3 | cloud_ext_k8s_cluster_admin_binding, gke_cloudsql_proxy_socket_access, initial_ssh_login_new_user |
| [T1078.004](https://attack.mitre.org/techniques/T1078/004) | Cloud Accounts | 5 | aks_managed_identity_token_abuse, cloud_ext_aws_iam_assume_role_repeated, cloud_ext_aws_root_account_login, eks_irsa_unusual_assume_role, gke_service_account_key_creation |
| [T1082](https://attack.mitre.org/techniques/T1082) | System Information Discovery | 3 | recon_system_info, sigma_cpu_info_access, sigma_kernel_version_read |
| [T1083](https://attack.mitre.org/techniques/T1083) | File and Directory Discovery | 2 | recon_sensitive_file_find, sigma_sensitive_dir_listing |
| [T1087](https://attack.mitre.org/techniques/T1087) | Account Discovery | 2 | eks_aws_config_dir_access, sigma_sudo_config_read |
| [T1087.001](https://attack.mitre.org/techniques/T1087/001) | Local Account | 2 | recon_user_enum, sigma_passwd_shadow_read |
| [T1090](https://attack.mitre.org/techniques/T1090) | Proxy | 3 | lateral_port_forward_ssh, netintr_socks_proxy_port, netintr_loopback_high_port |
| [T1090.001](https://attack.mitre.org/techniques/T1090/001) | — | 1 | c2_connect_to_tor_port |
| [T1090.003](https://attack.mitre.org/techniques/T1090/003) | Multi-hop Proxy | 1 | sigma_outbound_tor_ports |
| [T1095](https://attack.mitre.org/techniques/T1095) | Non-Application Layer Protocol | 5 | c2_raw_socket_shell, netintr_high_port_established, netintr_raw_socket_connection, netintr_connection_to_multicast, sigma_irc_c2_ports |
| [T1098](https://attack.mitre.org/techniques/T1098) | Account Manipulation | 8 | cloud_ext_aws_new_access_key, cloud_ext_gcp_service_account_key, cloud_ext_azure_rbac_assignment, fim_passwd_write, fim_shadow_write (+3 more) |
| [T1098.004](https://attack.mitre.org/techniques/T1098/004) | SSH Authorized Keys | 4 | fim_ssh_key_written, persist_sshd_config_write, persistence_ssh_authorized_keys, rootkit_ssh_authorized_keys_modified |
| [T1102](https://attack.mitre.org/techniques/T1102) | — | 1 | c2_paste_site_access |
| [T1105](https://attack.mitre.org/techniques/T1105) | Ingress Tool Transfer | 10 | lolbin_scp_download_to_tmp, lolbin_rsync_staging, lolbin_sftp_staging, lolbin_git_clone_to_tmp, lolbin_pip_download_to_tmp (+5 more) |
| [T1110](https://attack.mitre.org/techniques/T1110) | Brute Force | 2 | sigma_ssh_many_failed_auth, sigma_failed_login_syscall |
| [T1112](https://attack.mitre.org/techniques/T1112) | Modify Registry | 1 | mitre_dbus_config_modified |
| [T1132.001](https://attack.mitre.org/techniques/T1132/001) | — | 1 | c2_periodic_beacon_pattern |
| [T1133](https://attack.mitre.org/techniques/T1133) | External Remote Services | 4 | initial_vpn_unexpected_access, mitre_vpn_service_started, mitre_ngrok_tunnel, mitre_ngrok_dns_query |
| [T1134](https://attack.mitre.org/techniques/T1134) | Access Token Manipulation | 2 | mitre_token_impersonation_su, mitre_newuidmap_newgidmap |
| [T1136](https://attack.mitre.org/techniques/T1136) | Create Account | 1 | cloud_ext_aws_iam_user_created |
| [T1136.001](https://attack.mitre.org/techniques/T1136/001) | Local Account | 1 | rootkit_passwd_modified |
| [T1176](https://attack.mitre.org/techniques/T1176) | — | 1 | persist_xdg_autostart_write |
| [T1190](https://attack.mitre.org/techniques/T1190) | Exploit Public-Facing Application | 23 | appexploit_log4shell_jndi_lookup, appexploit_log4shell_ldap_port, appexploit_log4shell_rmi_port, appexploit_spring4shell_file_write, appexploit_struts2_ognl_shell (+18 more) |
| [T1195.001](https://attack.mitre.org/techniques/T1195/001) | Compromise Software Dependencies and Development Tools | 1 | appexploit_pip_install_malicious |
| [T1195.002](https://attack.mitre.org/techniques/T1195/002) | — | 1 | initial_package_postinstall_network |
| [T1203](https://attack.mitre.org/techniques/T1203) | Exploitation for Client Execution | 3 | appexploit_java_deser_ysoserial, appexploit_java_deser_network_port, appexploit_php_deser_chain |
| [T1218](https://attack.mitre.org/techniques/T1218) | System Binary Proxy Execution | 19 | lolbin_socat_shell, lolbin_nmap_script_exec, lolbin_strace_exec, lolbin_gdb_exec, lolbin_tclsh_exec (+14 more) |
| [T1219](https://attack.mitre.org/techniques/T1219) | — | 1 | c2_remote_access_tool |
| [T1222](https://attack.mitre.org/techniques/T1222) | File and Directory Permissions Modification | 4 | evasion_chmod_sensitive, sigma_chmod_executable_tmp, sigma_world_writable_dir_created, sigma_sensitive_file_chmod |
| [T1484](https://attack.mitre.org/techniques/T1484) | Domain Policy Modification | 2 | cloud_ext_gcp_project_iam_modified, mitre_nsswitch_modified |
| [T1485](https://attack.mitre.org/techniques/T1485) | — | 1 | ransomware_log_wipe |
| [T1486](https://attack.mitre.org/techniques/T1486) | — | 3 | ransomware_mass_rename, ransomware_encrypted_extension, ransomware_ransom_note |
| [T1490](https://attack.mitre.org/techniques/T1490) | — | 2 | ransomware_shadow_delete, ransomware_backup_tool_kill |
| [T1496](https://attack.mitre.org/techniques/T1496) | Resource Hijacking | 1 | appexploit_xmrig_download |
| [T1497.001](https://attack.mitre.org/techniques/T1497/001) | System Checks | 3 | mitre_sandbox_detect_proc_read, mitre_sandbox_detect_cpuid, mitre_vm_detect_dmi_read |
| [T1505](https://attack.mitre.org/techniques/T1505) | Server Software Component | 1 | cloud_ext_k8s_webhook_created |
| [T1505.003](https://attack.mitre.org/techniques/T1505/003) | Web Shell | 18 | persist_apache_conf_write, webshell_php_in_web_root, webshell_jsp_in_web_root, webshell_asp_written, webshell_script_write_via_web_process (+13 more) |
| [T1518](https://attack.mitre.org/techniques/T1518) | Software Discovery | 1 | mitre_software_enum_dpkg |
| [T1518.001](https://attack.mitre.org/techniques/T1518/001) | Security Software Discovery | 2 | mitre_software_enum_security_tools, recon_security_tools_enum |
| [T1525](https://attack.mitre.org/techniques/T1525) | — | 1 | eks_ecr_credential_helper_access |
| [T1528](https://attack.mitre.org/techniques/T1528) | — | 6 | aks_workload_identity_token_read, eks_irsa_token_read, eks_pod_identity_token_read, eks_irsa_unusual_assume_role, gke_workload_identity_endpoint_abuse (+1 more) |
| [T1530](https://attack.mitre.org/techniques/T1530) | Data from Cloud Storage | 3 | cloud_ext_aws_s3_bucket_public, cloud_ext_gcp_storage_public, cloud_ext_azure_storage_anonymous_access |
| [T1534](https://attack.mitre.org/techniques/T1534) | — | 1 | lateral_shared_volume_exec |
| [T1537](https://attack.mitre.org/techniques/T1537) | Transfer Data to Cloud Account | 1 | cloud_ext_aws_ec2_snapshot_copy |
| [T1542.003](https://attack.mitre.org/techniques/T1542/003) | — | 1 | integrity_grub_bootloader_write |
| [T1543](https://attack.mitre.org/techniques/T1543) | Create or Modify System Process | 1 | fim_init_d_script_written |
| [T1543.001](https://attack.mitre.org/techniques/T1543/001) | — | 1 | persistence_etc_init_write |
| [T1543.002](https://attack.mitre.org/techniques/T1543/002) | Systemd Service | 5 | persist_systemd_timer_created, persist_systemd_wants_symlink, persistence_systemd_new_service, sigma_systemd_service_created, sigma_systemd_timer_created |
| [T1546](https://attack.mitre.org/techniques/T1546) | Event Triggered Execution | 1 | fim_rc_local_modified |
| [T1546.004](https://attack.mitre.org/techniques/T1546/004) | Unix Shell Configuration Modification | 4 | fim_profile_modified, persist_profile_d_write, persist_etc_environment_write, persistence_shell_rc_write |
| [T1547.006](https://attack.mitre.org/techniques/T1547/006) | Kernel Modules and Extensions | 6 | privesc_sys_module_gained, rootkit_kmod_unsigned_load, rootkit_kmod_suspicious_name, rootkit_init_module_syscall, rootkit_kmod_from_tmp (+1 more) |
| [T1548](https://attack.mitre.org/techniques/T1548) | Abuse Elevation Control Mechanism | 2 | fim_polkit_policy_modified, sigma_prctl_dumpable |
| [T1548.001](https://attack.mitre.org/techniques/T1548/001) | Setuid and Setgid | 7 | privesc_sys_admin_gained, privesc_net_raw_gained, privesc_sys_ptrace_gained, privesc_caps_drop_all, privesc_setuid_gained (+2 more) |
| [T1548.002](https://attack.mitre.org/techniques/T1548/002) | Bypass User Account Control | 4 | privesc_net_admin_gained, privesc_sys_chroot_gained, privesc_setns_syscall, privesc_unshare_user_ns |
| [T1548.003](https://attack.mitre.org/techniques/T1548/003) | Sudo and Sudo Caching | 1 | fim_sudoers_written |
| [T1550.001](https://attack.mitre.org/techniques/T1550/001) | — | 1 | lateral_kubectl_exec_from_pod |
| [T1552](https://attack.mitre.org/techniques/T1552) | Unsecured Credentials | 4 | cloud_ext_k8s_secret_list, cloud_ext_k8s_etcd_access, sigma_sensitive_dir_listing, webshell_sensitive_file_read |
| [T1552.001](https://attack.mitre.org/techniques/T1552/001) | Credentials In Files | 15 | aks_service_principal_secret_access, aks_azure_linux_agent_access, aks_bootstrap_kubeconfig_access, cloud_ext_aws_secretsmanager_access, cloud_ext_azure_keyvault_secret_access (+10 more) |
| [T1552.003](https://attack.mitre.org/techniques/T1552/003) | — | 1 | cred_bash_history_read |
| [T1552.004](https://attack.mitre.org/techniques/T1552/004) | Private Keys | 2 | cred_ssh_private_key_read, fim_private_key_written |
| [T1552.005](https://attack.mitre.org/techniques/T1552/005) | Cloud Instance Metadata API | 10 | aks_imds_access, aks_managed_identity_token_abuse, appexploit_ssrf_gcp_metadata, cloud_ext_aws_imds_v1_access, cloud_ext_gcp_compute_metadata_access (+5 more) |
| [T1553.004](https://attack.mitre.org/techniques/T1553/004) | Install Root Certificate | 1 | fim_ca_cert_modified |
| [T1554](https://attack.mitre.org/techniques/T1554) | — | 1 | persist_git_hook_write |
| [T1555](https://attack.mitre.org/techniques/T1555) | — | 1 | cred_browser_store_read |
| [T1556.003](https://attack.mitre.org/techniques/T1556/003) | Pluggable Authentication Modules | 2 | persistence_pam_modified, rootkit_pam_module_added |
| [T1557](https://attack.mitre.org/techniques/T1557) | Adversary-in-the-Middle | 1 | mitre_sslstrip_proxy |
| [T1557.002](https://attack.mitre.org/techniques/T1557/002) | ARP Cache Poisoning | 1 | mitre_arp_spoof_raw_socket |
| [T1558](https://attack.mitre.org/techniques/T1558) | Steal or Forge Kerberos Tickets | 1 | mitre_keytab_file_read |
| [T1558.003](https://attack.mitre.org/techniques/T1558/003) | Kerberoasting | 1 | mitre_krb5_ccache_read |
| [T1561.001](https://attack.mitre.org/techniques/T1561/001) | — | 1 | ransomware_disk_wipe |
| [T1562](https://attack.mitre.org/techniques/T1562) | Impair Defenses | 1 | sigma_seccomp_filter_install |
| [T1562.001](https://attack.mitre.org/techniques/T1562/001) | Disable or Modify Tools | 5 | cloud_ext_aws_guardduty_disabled, cloud_ext_azure_sentinel_disabled, fim_apparmor_profile_modified, fim_selinux_config_modified, sigma_auditd_stopped |
| [T1562.004](https://attack.mitre.org/techniques/T1562/004) | Disable or Modify System Firewall | 2 | evasion_iptables_flush, sigma_iptables_flush |
| [T1562.006](https://attack.mitre.org/techniques/T1562/006) | — | 1 | evasion_auditd_stop |
| [T1562.008](https://attack.mitre.org/techniques/T1562/008) | Disable or Modify Cloud Logs | 1 | cloud_ext_aws_cloudtrail_stopped |
| [T1563.001](https://attack.mitre.org/techniques/T1563/001) | — | 1 | lateral_ssh_agent_socket_access |
| [T1564](https://attack.mitre.org/techniques/T1564) | Hide Artifacts | 1 | rootkit_hidden_proc_dir |
| [T1564.001](https://attack.mitre.org/techniques/T1564/001) | Hidden Files and Directories | 2 | rootkit_hidden_dir_dev, rootkit_large_hidden_file |
| [T1565.001](https://attack.mitre.org/techniques/T1565/001) | Stored Data Manipulation | 5 | fim_binary_replaced_in_system_dir, fim_library_replaced, fim_hosts_file_modified, fim_resolv_conf_modified, fim_network_config_modified |
| [T1566](https://attack.mitre.org/techniques/T1566) | — | 1 | initial_office_macro_exec |
| [T1567.002](https://attack.mitre.org/techniques/T1567/002) | — | 1 | exfil_cloud_sync_tool |
| [T1568](https://attack.mitre.org/techniques/T1568) | Dynamic Resolution | 1 | netintr_dns_high_entropy_query |
| [T1568.002](https://attack.mitre.org/techniques/T1568/002) | Domain Generation Algorithms | 1 | netintr_dga_domain_query |
| [T1570](https://attack.mitre.org/techniques/T1570) | — | 1 | lateral_tool_transfer_wget |
| [T1571](https://attack.mitre.org/techniques/T1571) | Non-Standard Port | 2 | c2_high_port_outbound, netintr_persistent_c2_beacon |
| [T1572](https://attack.mitre.org/techniques/T1572) | Protocol Tunneling | 5 | mitre_ngrok_tunnel, netintr_icmp_outbound_large, netintr_ssh_non_standard_port, netintr_http_on_non_web_port, netintr_gre_tunnel |
| [T1574.001](https://attack.mitre.org/techniques/T1574/001) | — | 1 | integrity_lib_replaced |
| [T1574.006](https://attack.mitre.org/techniques/T1574/006) | Dynamic Linker Hijacking | 6 | lolbin_ld_audit_set, persistence_ld_preload_env, rootkit_ld_preload_written, rootkit_ld_preload_env_set, rootkit_ld_library_path_suspicious (+1 more) |
| [T1574.007](https://attack.mitre.org/techniques/T1574/007) | Path Interception by PATH Environment Variable | 1 | lolbin_path_hijack_indicator |
| [T1583](https://attack.mitre.org/techniques/T1583) | Acquire Infrastructure | 1 | cloud_ext_aws_lambda_function_created |
| [T1584](https://attack.mitre.org/techniques/T1584) | Compromise Infrastructure | 1 | fim_hosts_file_modified |
| [T1601](https://attack.mitre.org/techniques/T1601) | — | 1 | integrity_container_runtime_modified |
| [T1609](https://attack.mitre.org/techniques/T1609) | Container Administration Command | 1 | cloud_ext_gcp_kubernetes_pod_exec |
| [T1610](https://attack.mitre.org/techniques/T1610) | Deploy Container | 3 | cloud_ext_k8s_privileged_pod, fim_docker_config_modified, fim_containerd_config_modified |
| [T1611](https://attack.mitre.org/techniques/T1611) | Escape to Host | 9 | aks_azure_linux_agent_access, aks_bootstrap_kubeconfig_access, appexploit_docker_socket_access, appexploit_containerd_socket_access, appexploit_cri_socket_access (+4 more) |
| [T1613](https://attack.mitre.org/techniques/T1613) | — | 1 | gke_kubelet_readonly_port_access |
| [T1620](https://attack.mitre.org/techniques/T1620) | Reflective Code Loading | 4 | mitre_reflective_elf_load, mitre_so_injection_via_proc, rootkit_anonymous_exec_memory, sigma_memfd_create_anonymous |

## Coverage by Tactic

**Initial Access** (TA0001): [██████████] 100%  
  Techniques with rules: T1190, T1133, T1195

**Execution** (TA0002): [██████████] 100%  
  Techniques with rules: T1059, T1203, T1053, T1609

**Persistence** (TA0003): [██████████] 100%  
  Techniques with rules: T1543, T1546, T1547, T1505, T1098

**Privilege Escalation** (TA0004): [██████████] 100%  
  Techniques with rules: T1548, T1611, T1134

**Defense Evasion** (TA0005): [██████████] 100%  
  Techniques with rules: T1027, T1036, T1070, T1562, T1497, T1620

**Credential Access** (TA0006): [██████████] 100%  
  Techniques with rules: T1003, T1040, T1110, T1552, T1558, T1557

**Discovery** (TA0007): [████████░░] 83%  
  Techniques with rules: T1046, T1082, T1083, T1087, T1518

**Lateral Movement** (TA0008): [█████░░░░░] 50%  
  Techniques with rules: T1021

**Collection** (TA0009): [██████████] 100%  
  Techniques with rules: T1530

**Exfiltration** (TA0010): [██████████] 100%  
  Techniques with rules: T1048, T1537

**Command and Control** (TA0011): [██████████] 100%  
  Techniques with rules: T1071, T1090, T1095, T1572, T1568, T1571

**Impact** (TA0040): [██████████] 100%  
  Techniques with rules: T1496, T1565


## Untagged Rules (121)

Rules without MITRE ATT&CK technique tags:

- `cis_5_1_1_cluster_admin_usage` — CIS 5.1.1: Cluster-admin role usage
- `cis_5_1_3_secret_access` — CIS 5.1.3: Direct secret access detected
- `cis_5_2_1_privileged_container` — CIS 5.2.1: Privileged container detected
- `cis_5_2_5_privilege_escalation` — CIS 5.2.5: Privilege escalation detected
- `cloud_001` — STS AssumeRole from unknown IP
- `cloud_002` — Secrets Manager GetSecretValue (access to sensitive credentials)
- `cloud_003` — Kubernetes pods/exec from cloud API (kubectl exec)
- `cloud_004` — Cloud metadata API access (credential theft via IMDS)
- `cloud_005` — New IAM access key created (persistence)
- `cloud_006` — GCP service account key created (persistence)
- `cloud_007` — Cloud API access denied (possible credential probing)
- `container_escape_mount` — Container Escape: Mount syscall from container
- `container_escape_host_mount` — Container Escape: Mount of host filesystem path
- `container_escape_nsenter` — Container Escape: Namespace enter attempt
- `container_escape_unshare_user` — Container Escape: User namespace creation
- `container_escape_sysrq_trigger` — Container Escape: SysRq trigger write
- `container_escape_kmem_access` — Container Escape: Kernel memory device access
- `container_escape_module_access` — Container Escape: Kernel module access
- `container_escape_cap_sys_admin` — Container Escape: CAP_SYS_ADMIN operation
- `container_escape_pivot_root` — Container Escape: pivot_root syscall
- ... and 101 more