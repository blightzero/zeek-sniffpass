@load base/protocols/http
@load base/frameworks/notice

module SNIFFPASS;

global username_fields = set("ACCOUNT","ACCT","ACCTNAME","AHD_USERNAME","ALIAS","AUTH","DOMAIN","EMAIL","FORM_LOGINNAME","_ID","ID","J_USERNAME","LOG","LOGIN","LOGIN_EMAIL","LOGINEMAIL","LOGIN_ID","LOGINID","LOGINNAME","LOGIN_USERNAME","LOGINUSERNAME","MAILADDRESS","MEMBER","MEMBERNAME","MN","NAME","NICKNAME","POP_LOGIN","PSEUDO","SCREENAME","SESSION_KEY","SESSIONKEY","SIGN-IN","UID","UIN","ULOGIN","UNAME","UNICKNAME","USER","USER_ID","USERID","_USERNAME","USER_NAME","USERNAME","USR","USRNAME","WPNAME");
global password_fields = set("ADDITIONAL_INFO","AHD_PASSWORD","FORM_PW","J_PASSWORD","LOGIN_PASSWORD","LOGINPASSWORD","LOGIN_PASSWORDPASSWORT","PASS","PASSWD","_PASSWORD","PASSWORD","PASSWORT","PASSWRD","PSW","PW","PWD","SECRET","SESSION_PASSWORD","SESSIONPASSWORD","UPASSWD","UPASSWORD","USERPASSWORD","WPPASSWORD");

type CredPost: record {
    userId: string &optional;
    user: string &optional;
    email: string &optional;
    pass: string &optional;
    password: string &optional;
};

type Credential: record {
    username: string;
    password: string;
};

global credentials_seen: event(cred: Credential);
global credentials_seen_detailed: event(cred: Credential, dest_ip: addr, dest_port: port, url :string);

export {
    const log_username = T &redef;
    const log_password_plaintext = F &redef;
    const log_password_md5 = F &redef;
    const log_password_sha1 = F &redef;
    const log_password_sha256 = F &redef;
    const post_body_limit = 300 &redef;
    const notice_log_enable = T &redef;
    const broker_enable = F &redef;
    const broker_host = "127.0.0.1" &redef;
    const broker_port = 9999/tcp &redef;
    const broker_topic = "/sniffpass/credentials_seen" &redef;
    const broker_detailed = F &redef;
}

type SPStorage: record {
    inspect_post_data: bool &default=F &log;
    inspect_post_data_json: bool &default=F &log;
    post_data: string &log &optional;
};

redef record HTTP::Info += {
    post_username: string &log &optional;
    post_password_plain: string &log &optional;
    post_password_md5: string &log &optional;
    post_password_sha1: string &log &optional;
    post_password_sha256: string &log &optional;
};

redef enum Notice::Type += {
    HTTP_POST_Password_Seen,
};

redef record connection += {
    sp: SPStorage &optional;
};

function cred_handler(cred: Credential, c: connection)
{
    if ( SNIFFPASS::broker_detailed )
    {
        local dest_ip = c$id$resp_h;
        local dest_port = c$id$resp_p;
        local url = c$http$host + c$http$uri;
        event SNIFFPASS::credentials_seen_detailed(cred, dest_ip, dest_port, url);
    }
    else
    {
        event SNIFFPASS::credentials_seen(cred);
    }
}

event http_header(c: connection, is_orig: bool, name: string, value: string)
{
    if ( is_orig && c$http$method == "POST") {
        if (to_upper(name) == "CONTENT-TYPE") {
            if (to_upper(value) == "APPLICATION/X-WWW-FORM-URLENCODED")
            {
                if ( ! c?$sp )
                    c$sp = SPStorage();

                c$sp$inspect_post_data = T;
                c$sp$post_data = "";
            }
            if (to_upper(value) == "APPLICATION/JSON") 
            {
                if ( ! c?$sp )
                    c$sp = SPStorage();

                c$sp$inspect_post_data = T;
                c$sp$inspect_post_data_json = T;
                c$sp$post_data = "";
            }
        }
  }
}

event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
  {
    if ( is_orig && c?$sp && c$sp$inspect_post_data ) {
        if ( |c$sp$post_data| >= post_body_limit )
            return;

        c$sp$post_data += data;

        if ( |c$sp$post_data| > post_body_limit )
            c$sp$post_data = c$sp$post_data[0:post_body_limit] + "~";
    }
  }

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat)
{
    if ( is_orig && c?$sp && c$sp$inspect_post_data )
    {

        local post_parsed = split_string(c$sp$post_data, /&/);
        local password_seen = F;
        local username_value = "";
        local password_value = "";

        if(c$sp$inspect_post_data_json){

            local u_parts: string_vec;
            local p_parts: string_vec;
            local user_pattern = set_to_regex(username_fields, "\\\"(?i:~~)\\\"([[:space:]]*):([[:space:]]*)\\\"[^\"]*\\\"");
            local password_pattern = set_to_regex(password_fields, "\\\"(?i:~~)\\\"([[:space:]]*):([[:space:]]*)\\\"[^\"]*\\\"");

            local user = find_all(c$sp$post_data, user_pattern);
            local passext = find_all(c$sp$post_data, password_pattern);

            for ( u in user){
                    u_parts = split_string(u, /\"/);
                    if ( |u_parts| == 5) {
                        username_value = u_parts[3];
                        c$http$post_username = username_value;
                    }
            }

            for ( pp in passext){
                    p_parts = split_string(pp, /\"/);
                    if ( |p_parts| == 5) {
                        password_value = p_parts[3];
                        password_seen = T;
                        if ( log_password_plaintext )
                            c$http$post_password_plain = password_value;
                        if ( log_password_md5 )
                            c$http$post_password_md5 = md5_hash(password_value);
                        if ( log_password_sha1 )
                            c$http$post_password_sha1 = sha1_hash(password_value);
                        if ( log_password_sha256 )
                            c$http$post_password_sha256 = sha256_hash(password_value);
                    }
            }

        }
        else {
            for (p in post_parsed) {
                local kv = split_string1(post_parsed[p], /=/);
                if (to_upper(kv[0]) in username_fields) {
                    username_value = kv[1];
                    c$http$post_username = username_value;
                }
                if (to_upper(kv[0]) in password_fields) {
                    password_value = kv[1];
                    password_seen = T;

                    if ( log_password_plaintext )
                        c$http$post_password_plain = password_value;
                    if ( log_password_md5 )
                        c$http$post_password_md5 = md5_hash(password_value);
                    if ( log_password_sha1 )
                        c$http$post_password_sha1 = sha1_hash(password_value);
                    if ( log_password_sha256 )
                        c$http$post_password_sha256 = sha256_hash(password_value);
                }
            }
        }
        if ( password_seen ) {
            if ( |username_value| > 0 )
            {
                local cred = Credential($username = username_value, $password = password_value);
                cred_handler(cred, c);

                if (notice_log_enable) {
                    NOTICE([$note=HTTP_POST_Password_Seen,
                    $msg="Password found for user " + username_value,
                    $conn=c ]);
                }
            }
            else
            {
                if (notice_log_enable) {
                    NOTICE([$note=HTTP_POST_Password_Seen,
                    $msg="Password found",
                    $conn=c ]);
                }
            }
        }
    }
}

event zeek_init()
{
    # Only use Broker if it's available
    @ifdef (Broker::auto_publish)
        if (SNIFFPASS::broker_enable)
        {
            # When in cluster mode, only workers should connect to broker_host
            if ( (Cluster::is_enabled() && Cluster::local_node_type() == Cluster::WORKER ) || ! Cluster::is_enabled() ) {
                Broker::peer(SNIFFPASS::broker_host, SNIFFPASS::broker_port);
                Broker::auto_publish(SNIFFPASS::broker_topic, SNIFFPASS::credentials_seen);
                Broker::auto_publish(SNIFFPASS::broker_topic, SNIFFPASS::credentials_seen_detailed);
            }
        }
    @endif
}
