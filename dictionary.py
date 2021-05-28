import numpy as np
from sklearn.preprocessing import scale

def attack_features(duration,src_bytes,dst_bytes,land,wrong_fragment,urgent,hot,num_failed_logins,logged_in,num_compromised,root_shell,su_attempted,num_file_creations,num_shells,num_access_files,num_outbound_cmds,is_host_login,is_guest_login,count,srv_count,serror_rate,rerror_rate,same_srv_rate,diff_srv_rate,srv_diff_host_rate,dst_host_count,dst_host_srv_count,dst_host_diff_srv_rate,dst_host_same_src_port_rate,dst_host_srv_diff_host_rate,protocol_type,service,flag):

  attack_features_dict = {
    "duration":0,
    "src_bytes":0,
    "dst_bytes":0,
    "land":0,
    "wrong_fragment":0,
    "urgent":0,
    "hot":0,
    "num_failed_logins":0,
    "logged_in":0,
    "num_compromised":0,
    "root_shell":0,
    "su_attempted":0,
    "num_file_creations":0,
    "num_shells":0,
    "num_access_files":0,
    "num_outbound_cmds":0,
    "is_host_login":0,
    "is_guest_login":0,
    "count":0,
    "srv_count":0,
    "serror_rate":0,
    "rerror_rate":0,
    "same_srv_rate":0,
    "diff_srv_rate":0,
    "srv_diff_host_rate":0,
    "dst_host_count":0,
    "dst_host_srv_count":0,
    "dst_host_diff_srv_rate":0,
    "dst_host_same_src_port_rate":0,
    "dst_host_srv_diff_host_rate":0,
    "protocol_type_tcp":0,
    "protocol_type_udp":0,
    "service_X11":0,
    "service_Z39_50":0,
    "service_auth":0,
    "service_bgp":0,
    "service_courier":0,
    "service_csnet_ns":0,
    "service_ctf":0,
    "service_daytime":0,
    "service_discard":0,
    "service_domain":0,
    "service_domain_u":0,
    "service_echo":0,
    "service_eco_i":0,
    "service_ecr_i":0,
    "service_efs":0,
    "service_exec":0,
    "service_finger":0,
    "service_ftp":0,
    "service_ftp_data":0,
    "service_gopher":0,
    "service_hostnames":0,
    "service_http":0,
    "service_http_443":0,
    "service_imap4":0,
    "service_iso_tsap":0,
    "service_klogin":0,
    "service_kshell":0,
    "service_ldap":0,
    "service_link":0,
    "service_login":0,
    "service_mtp":0,
    "service_name":0,
    "service_netbios_dgm":0,
    "service_netbios_ns":0,
    "service_netbios_ssn":0,
    "service_netstat":0,
    "service_nnsp":0,
    "service_nntp":0,
    "service_ntp_u":0,
    "service_other":0,
    "service_pm_dump":0,
    "service_pop_2":0,
    "service_pop_3":0,
    "service_printer":0,
    "service_private":0,
    "service_red_i":0,
    "service_remote_job":0,
    "service_rje":0,
    "service_shell":0,
    "service_smtp":0,
    "service_sql_net":0,
    "service_ssh":0,
    "service_sunrpc":0,
    "service_supdup":0,
    "service_systat":0,
    "service_telnet":0,
    "service_tftp_u":0,
    "service_tim_i":0,
    "service_time":0,
    "service_urh_i":0,
    "service_urp_i":0,
    "service_uucp":0,
    "service_uucp_path":0,
    "service_vmnet":0,
    "service_whois":0,
    "flag_REJ":0,
    "flag_RSTO":0,
    "flag_RSTOS0":0,
    "flag_RSTR":0,
    "flag_S0":0,
    "flag_S1":0,
    "flag_S2":0,
    "flag_S3":0,
    "flag_SF":0,
    "flag_SH":0,
  }

  attack_features_dict['duration'] = duration
  attack_features_dict['src_bytes'] = src_bytes
  attack_features_dict['dst_bytes'] = dst_bytes
  attack_features_dict['land'] = land
  attack_features_dict['wrong_fragment'] = wrong_fragment
  attack_features_dict['urgent'] = urgent
  attack_features_dict['hot'] = hot
  attack_features_dict['num_failed_logins'] = num_failed_logins
  attack_features_dict['logged_in'] = logged_in
  attack_features_dict['num_compromised'] = num_compromised
  attack_features_dict['root_shell'] = root_shell
  attack_features_dict['su_attempted'] = su_attempted
  attack_features_dict['num_file_creations'] = num_file_creations
  attack_features_dict['num_shells'] = num_shells
  attack_features_dict['num_access_files'] = num_access_files
  attack_features_dict['num_outbound_cmds'] = num_outbound_cmds
  attack_features_dict['is_host_login'] = is_host_login
  attack_features_dict['is_guest_login'] = is_guest_login
  attack_features_dict['count'] = count
  attack_features_dict['srv_count'] = srv_count
  attack_features_dict['serror_rate'] = serror_rate
  attack_features_dict['rerror_rate'] = rerror_rate
  attack_features_dict['same_srv_rate'] = same_srv_rate
  attack_features_dict['diff_srv_rate'] = diff_srv_rate
  attack_features_dict['srv_diff_host_rate'] = srv_diff_host_rate
  attack_features_dict['dst_host_count'] = dst_host_count
  attack_features_dict['dst_host_srv_count'] = dst_host_srv_count
  attack_features_dict['dst_host_diff_srv_rate'] = dst_host_diff_srv_rate
  attack_features_dict['dst_host_same_src_port_rate'] = dst_host_same_src_port_rate
  attack_features_dict['dst_host_srv_diff_host_rate'] = dst_host_srv_diff_host_rate
  attack_features_dict[protocol_type] = 1
  attack_features_dict[service] = 1
  attack_features_dict[flag] = 1

  data = list(attack_features_dict.values())
  input_arr = np.array(data)
  input_arr = scale(input_arr)
  input_arr = input_arr.reshape(-1,107)
  return input_arr
