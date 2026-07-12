-- wrk Lua script for simulating SQL injection attacks
-- This script generates various SQL injection payloads to test ebpf-guard detection

math.randomseed(os.time())

-- SQL Injection payloads
local sqli_payloads = {
    "' OR '1'='1",
    "' OR 1=1--",
    "admin'--",
    "' UNION SELECT NULL--",
    "' OR '1'='1'--",
    "1' OR '1'='1",
    "admin' /*",
    "' OR 1=1#",
    "x' OR 1=1--",
    "'; DROP TABLE users--",
    "' UNION SELECT password FROM users--"
}

-- Brute force usernames
local usernames = {
    "admin", "administrator", "root", "test", "user",
    "jim", "alice", "bob", "eve", "mallory"
}

-- Brute force passwords
local passwords = {
    "password", "123456", "admin", "root", "test123",
    "welcome", "letmein", "secret", "password1"
}

local function random_sqli()
    return sqli_payloads[math.random(#sqli_payloads)]
end

local function random_bruteforce()
    return usernames[math.random(#usernames)]
end

local function random_password()
    return passwords[math.random(#passwords)]
end

request = function()
    local method = "POST"
    local path = "/rest/user/login"

    -- Alternate between SQLi and brute force
    local attack_type = math.random(2)

    if attack_type == 1 then
        -- SQL Injection attack
        local body = '{"email": "' .. random_sqli() .. '", "password": "test"}'
        local headers = {}
        headers["Content-Type"] = "application/json"
        return wrk.format(method, path, headers, body)
    else
        -- Brute force attack
        local user = random_bruteforce()
        local pass = random_password()
        local body = '{"email": "' .. user .. '@test.com", "password": "' .. pass .. '"}'
        local headers = {}
        headers["Content-Type"] = "application/json"
        return wrk.format(method, path, headers, body)
    end
end

-- Called after each request
response = function(status, headers, body)
    -- Could log successful detections here
    if status == 200 or status == 401 then
        -- Request got through (possibly blocked by ebpf-guard)
    end
end
