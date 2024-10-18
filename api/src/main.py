from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from ldap3 import Server, Connection, ALL, MODIFY_REPLACE
from typing import List
from passlib.hash import ldap_salted_sha1
from ldap3.core.exceptions import LDAPException

LDAP_SERVER = 'ldap'  # LDAP service name from docker-compose
LDAP_PORT = 1389

LDAP_ADMIN_DN = 'cn=admin,dc=example,dc=org'
LDAP_ADMIN_PASSWORD = 'adminpassword'
BASE_DN = 'dc=example,dc=org'
USER_BASE_DN = 'ou=users,' + BASE_DN

app = FastAPI()

class User(BaseModel):
    username: str
    password: str

class AuthUser(BaseModel):
    username: str
    password: str

class ChangePassword(BaseModel):
    username: str
    old_password: str
    new_password: str

def get_ldap_connection():
    server = Server(LDAP_SERVER, port=LDAP_PORT, get_info=ALL)
    conn = Connection(server, user=LDAP_ADMIN_DN, password=LDAP_ADMIN_PASSWORD, auto_bind=True)
    return conn

@app.post("/add_user")
def add_user(user: User):
    conn = get_ldap_connection()
    dn = f'uid={user.username},{USER_BASE_DN}'
    # Check if user already exists
    conn.search(USER_BASE_DN, f'(uid={user.username})')
    if conn.entries:
        conn.unbind()
        raise HTTPException(status_code=400, detail="User already exists")

    hashed_password = ldap_salted_sha1.encrypt(user.password)
    attrs = {
        'objectClass': ['inetOrgPerson', 'top', 'customUser'],
        'cn': user.username, # must-have inetOrgPerson
        'sn': user.username, # must-have inetOrgPerson
        'mail': user.username + '@example.org', # optional inetOrgPerson

        'uid': user.username, # must-have customUser  
        'userPassword': hashed_password, # must-have customUser 
        
        'memberOf': ['user', 'admin', 'editor'],
        'writeUser': False,
        'writeConfig': False,
        'limitVdos': 10,
    }
    success = conn.add(dn, attributes=attrs)
    conn.unbind()
    if not success:
        raise HTTPException(status_code=400, detail=f"Failed to add user: {conn.result['description']}")
    return {"message": "User added successfully"}


@app.post("/authenticate")
def authenticate_user(auth_user: AuthUser):
    server = Server(LDAP_SERVER, port=LDAP_PORT, get_info=ALL)
    user_dn = f'uid={auth_user.username},{USER_BASE_DN}'
    conn = Connection(server, user=user_dn, password=auth_user.password)
    if not conn.bind():
        raise HTTPException(status_code=401, detail="Authentication failed")
    conn.unbind()
    return {"message": "Authentication successful"}

@app.post("/change_password")
def change_password(change_pw: ChangePassword):
    user_dn = f'uid={change_pw.username},{USER_BASE_DN}'
    # Authenticate user with old password
    user_conn = Connection(Server(LDAP_SERVER, port=LDAP_PORT), user=user_dn, password=change_pw.old_password)
    if not user_conn.bind():
        raise HTTPException(status_code=401, detail="Authentication failed")
    
    hashed_new_password = ldap_salted_sha1.hash(change_pw.new_password)
    success = user_conn.modify(user_dn, {'userPassword': [(MODIFY_REPLACE, [hashed_new_password])]})
    user_conn.unbind()
    if not success:
        raise HTTPException(status_code=400, detail=f"Failed to change password: {user_conn.result['description']}")
    return {"message": "Password changed successfully"}


@app.delete("/user/{username}")
def delete_user(username: str):
    conn = get_ldap_connection()
    dn = f'uid={username},{USER_BASE_DN}'
    success = conn.delete(dn)
    conn.unbind()
    if not success:
        raise HTTPException(status_code=400, detail=f"Failed to delete user: {conn.result['description']}")
    return {"message": "User deleted successfully"}

@app.get("/users")
def list_users():
    conn = get_ldap_connection()
    conn.search(USER_BASE_DN, '(objectClass=inetOrgPerson)', attributes=['uid'])
    users = [entry['attributes']['uid'][0] for entry in conn.response]
    conn.unbind()
    return users

@app.get("/user/{username}")
def get_user_info(username: str):
    conn = get_ldap_connection()
    search_filter = f"(uid={username})"
    attributes = ['cn', 'sn', 'uid', 'mail', 'writeUser', 'userPassword']
    try:
        conn.search(USER_BASE_DN, search_filter, attributes=attributes)
        if not conn.entries:
            conn.unbind()
            raise HTTPException(status_code=404, detail="User not found")
        user_entry = conn.entries[0]
        user_info = {
            'cn': user_entry.cn.value,
            'sn': user_entry.sn.value,
            'uid': user_entry.uid.value,
            'userPassword': user_entry.userPassword.value if 'userPassword' in user_entry else None,
            'writeUser': user_entry.writeUser.value if 'writeUser' in user_entry else None
        }
        conn.unbind()
        return user_info
    except LDAPException as e:
        conn.unbind()
        raise HTTPException(status_code=500, detail=f"LDAP error: {str(e)}")